//! Just enough JSON for the AI explanation: escape strings for a request body we
//! build with `format!`, and parse the API's response. Keeps the tool crate-free.

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn num(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }
    pub fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(v) => v,
            _ => &[],
        }
    }
}

/// A JSON string literal, quotes included.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn parse(text: &str) -> Result<Json, String> {
    let mut p = Parser { s: text.as_bytes(), i: 0, depth: 0 };
    let v = p.value()?;
    p.ws();
    if p.i != p.s.len() {
        return Err(format!("JSON 뒤에 남은 내용 (위치 {})", p.i));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    depth: u32,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn err<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("JSON 해석 실패: {what} (위치 {})", self.i))
    }

    fn eat(&mut self, lit: &str) -> bool {
        if self.s[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        if self.depth > 64 {
            return self.err("너무 깊은 중첩");
        }
        match self.s.get(self.i) {
            None => self.err("내용 없음"),
            Some(b'{') => {
                self.i += 1;
                self.depth += 1;
                let mut fields = Vec::new();
                self.ws();
                if self.eat("}") {
                    self.depth -= 1;
                    return Ok(Json::Obj(fields));
                }
                loop {
                    self.ws();
                    let Json::Str(k) = self.string()? else { unreachable!() };
                    self.ws();
                    if !self.eat(":") {
                        return self.err("':' 필요");
                    }
                    let v = self.value()?;
                    fields.push((k, v));
                    self.ws();
                    if self.eat(",") {
                        continue;
                    }
                    if self.eat("}") {
                        self.depth -= 1;
                        return Ok(Json::Obj(fields));
                    }
                    return self.err("',' 또는 '}' 필요");
                }
            }
            Some(b'[') => {
                self.i += 1;
                self.depth += 1;
                let mut items = Vec::new();
                self.ws();
                if self.eat("]") {
                    self.depth -= 1;
                    return Ok(Json::Arr(items));
                }
                loop {
                    items.push(self.value()?);
                    self.ws();
                    if self.eat(",") {
                        continue;
                    }
                    if self.eat("]") {
                        self.depth -= 1;
                        return Ok(Json::Arr(items));
                    }
                    return self.err("',' 또는 ']' 필요");
                }
            }
            Some(b'"') => self.string(),
            Some(b't') if self.eat("true") => Ok(Json::Bool(true)),
            Some(b'f') if self.eat("false") => Ok(Json::Bool(false)),
            Some(b'n') if self.eat("null") => Ok(Json::Null),
            Some(c) if *c == b'-' || c.is_ascii_digit() => {
                let start = self.i;
                while self.i < self.s.len() && matches!(self.s[self.i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                    self.i += 1;
                }
                let t = std::str::from_utf8(&self.s[start..self.i]).unwrap_or("");
                t.parse::<f64>().map(Json::Num).or_else(|_| self.err("숫자 형식"))
            }
            Some(_) => self.err("알 수 없는 값"),
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let h = self.s.get(self.i..self.i + 4).and_then(|b| std::str::from_utf8(b).ok()).and_then(|t| u32::from_str_radix(t, 16).ok());
        match h {
            Some(v) => {
                self.i += 4;
                Ok(v)
            }
            None => self.err("\\u 형식"),
        }
    }

    fn string(&mut self) -> Result<Json, String> {
        if !self.eat("\"") {
            return self.err("문자열 필요");
        }
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(&c) = self.s.get(self.i) else { return self.err("닫히지 않은 문자열") };
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let Some(&e) = self.s.get(self.i) else { return self.err("잘린 이스케이프") };
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xD800..0xDC00).contains(&cp) && self.eat("\\u") {
                                let lo = self.hex4()?;
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo.wrapping_sub(0xDC00) & 0x3FF);
                            }
                            char::from_u32(cp).unwrap_or('\u{FFFD}')
                        }
                        _ => return self.err("알 수 없는 이스케이프"),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                c => out.push(c),
            }
        }
        Ok(Json::Str(String::from_utf8_lossy(&out).into_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_strings() {
        let s = "줄1\n\"따옴표\" \\ 탭\t\u{1}";
        assert_eq!(parse(&quote(s)).unwrap(), Json::Str(s.into()));
    }

    #[test]
    fn parses_api_shape() {
        let v = parse(r#"{"content":[{"type":"thinking","thinking":""},{"type":"text","text":"{\"a\":1}"}],"stop_reason":"end_turn","usage":{"input_tokens":12,"output_tokens":3.5e1},"x":[true,false,null],"u":"😀é"}"#).unwrap();
        assert_eq!(v.get("stop_reason").and_then(Json::str), Some("end_turn"));
        assert_eq!(v.get("content").unwrap().arr()[1].get("text").and_then(Json::str), Some("{\"a\":1}"));
        assert_eq!(v.get("usage").and_then(|u| u.get("output_tokens")).and_then(Json::num), Some(35.0));
        assert_eq!(v.get("u").and_then(Json::str), Some("😀é"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("{\"a\":}").is_err());
        assert!(parse("[1,2").is_err());
        assert!(parse("{} x").is_err());
        assert!(parse(&"[".repeat(100)).is_err());
    }
}
