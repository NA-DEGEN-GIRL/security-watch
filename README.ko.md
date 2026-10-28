# security-watch

[English](README.md) · **한국어**

Windows PC와, 이 PC에서 SSH로 관리하는 Linux 서버들을 지켜보는 작은 보안 모니터입니다.
더블클릭하면 대시보드 창이 열리고 침투 흔적과 위험한 노출을 실시간으로 보여줍니다.
인터넷에 열린 RDP/SSH, 공인 IP에서 들어온 로그인, 비밀번호 대입 시도, 새로 생긴 계정·키·포트·자동실행 항목 등이 대상입니다.

![대시보드 (데모 데이터, 주소는 문서용 예시)](docs/dashboard.png)
*대시보드 (데모 데이터, 주소는 문서용 예시)*

- **읽기 전용:** 점검하는 서버와 PC의 상태를 바꾸지 않습니다.
- **외부 라이브러리 없음:** Rust 표준 라이브러리만 쓰고, Windows에 기본으로 있는 `ssh`, PowerShell, Edge를 이용합니다. 서버에는 아무것도 설치하지 않으며, SSH로 셸 스크립트를 실행해서 점검합니다.
- **개인 정보 분리:** 호스트 이름, 기준선, 리포트는 git에서 제외되는 폴더에만 저장됩니다.

## 대시보드

| 영역 | 내용 |
|---|---|
| 상단 | 전체 상태, 기준 시점, 전체 검사 주기, "지금 전체 검사" |
| 호스트 카드 | 실시간 연결 상태, 외부 접근·인증 실패·로그인·현재 연결 수 |
| 점검 결과 | 대상별 최근 전체 검사 결과, 기준선 변경 사항과 승인 버튼 |
| 실시간 이벤트 | SSH/RDP 로그인과 실패, sudo 실패, 방화벽 차단, 새 외부 연결 |
| 들어와 있는 연결 | 열린 포트로 들어온 연결, 5초마다 갱신 (공인 IP는 빨간색) |

갱신 주기:

- **실시간 (수 초):** 서버마다 SSH 연결을 하나씩 계속 열어 두고, journal에 기록되는 SSH·sudo·방화벽 이벤트를 발생 즉시 받습니다. 이 PC는 RDP·로그인 이벤트를 5초마다 확인합니다. 같은 출처의 반복 이벤트는 한 줄("×N")로 묶습니다.
- **정기 전체 검사 (분 단위):** 아래의 무거운 점검을 5분마다(창에서 1~60분으로 변경) 또는 버튼을 누를 때 실행합니다.
- **기준 시점:** "기준 시점을 지금으로"를 누르면 그 이전 로그 기록은 점검 결과에서 빠집니다. 노출을 막은 뒤 누르면, 이미 조치한 과거 공격이 계속 표시되지 않습니다. 기준선 비교와 실시간 이벤트에는 영향이 없습니다.

## 점검 항목

**이 PC (Windows)**
- RDP 켜짐/NLA 여부, **공인 IP**에서 들어온 RDP 접속과 로그인 실패(공유기가 RDP를 인터넷에 열어 둔 신호), 대량 접속으로 이벤트 로그가 덮어써진 흔적, RDP 로그인
- Windows 로그인 실패(이벤트 4625, "관리자 권한으로 실행" 필요)
- Defender 실시간 보호, Windows 방화벽 프로필, OpenSSH 서버
- 기준선: 열린 포트, 로컬 계정, 관리자 그룹, Run 키·시작프로그램, Microsoft 외 예약 작업, 자동 시작 서비스

**Linux 서버 (`ssh <별칭>`으로 접속)**
- SSH 실패와 로그인 성공을 공인/내부 IP로 나눠 집계. `lan`(공유기 안쪽)으로 지정한 서버는 공인 IP 접근이 하나라도 있으면 '위험'
- 비밀번호 방식 SSH 로그인, sudo 비밀번호 실패, ufw가 차단한 공인 IP 패킷
- root 외 UID 0 계정, `/etc/ld.so.preload`, `/tmp`·`/dev/shm`에서 실행 중인 프로세스, 임시 폴더의 새 실행 파일(ELF/스크립트), 재부팅 필요 여부
- 기준선: 열린 포트, 로그인 가능한 계정, `authorized_keys` 지문, 중요 파일(`passwd`, `shadow`, `sudoers`, `sshd_config`, PAM), systemd 유닛, cron 작업

## 설치

1. 빌드: `cargo build --release`
2. git에서 제외되는 개인 폴더를 만들고 exe를 복사합니다.
   ```
   mkdir .private
   copy target\release\security-watch.exe .private\
   ```
3. 한 번 실행하면 `.private\security-watch.conf`가 생깁니다. 서버를 추가합니다.
   ```
   local
   host my-server lan      # ~/.ssh/config의 Host 별칭, 키 인증 접속
   host my-vps public      # 인터넷에 직접 열린 서버: 공인 IP 대입 시도는 '정보'로만 집계
   ```
4. `.private\security-watch.exe`를 더블클릭합니다. 창을 닫으면 프로그램도 종료됩니다.

서버 요구 사항: 비밀번호 입력 없는 키 인증 SSH(`BatchMode`), 그리고 journal 읽기 권한(`adm` 또는 `systemd-journal` 그룹) 또는 비밀번호 없는 `sudo`. journal을 읽을 수 없으면 추측하지 않고 그 사실을 표시합니다. `sudo`가 없으면 다른 사용자의 연결은 프로세스 이름이 "권한 필요"로 나옵니다.

`security-watch.exe --once`는 텍스트 리포트를 한 번 출력하고 `.private\reports\`에 저장합니다(예약 작업용).

## 파일

```
.private/
  security-watch.conf     점검 대상
  state/<host>.baseline   승인된 기준선
  state/watch_since       기준 시점
  state/<host>.lastrun    마지막 검사 구간 끝 (--once)
  state/ui.lock, ui.log   실행 중인 대시보드(포트+토큰), 동작 로그
  ui-profile/             대시보드 창용 Edge 프로필
  reports/report-*.txt    --once 리포트
```

exe가 있는 폴더에 `security-watch.conf`가 있으면 그 폴더를 대신 쓰므로, exe만 복사해서 다른 곳에서도 쓸 수 있습니다.

## 보안 설계

- 화면은 `127.0.0.1`에서만 제공합니다. 모든 요청에 실행할 때마다 새로 만드는 무작위 토큰과 루프백 `Host` 헤더가 있어야 해서, 다른 프로그램이나 웹페이지가 상태를 읽거나 기준선을 승인할 수 없습니다(CSRF, DNS 리바인딩 방지).
- 자식 프로세스(`ssh`, PowerShell)는 kill-on-close Job Object 안에서 실행되므로, 프로그램이 강제 종료돼도 남지 않습니다.
- 원격 스크립트는 로그와 시스템 상태를 읽기만 합니다. `src/probe_linux.sh`, `src/live_linux.sh`에서 확인할 수 있습니다.

## 라이선스

MIT
