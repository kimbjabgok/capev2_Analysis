# CAPEv2 Report Analyzer

CAPEv2 샌드박스의 `report.json`을 분석하여 IOC 추출, 커스텀 탐지, MITRE ATT&CK 매핑, AI 분석, HTML/PDF 리포트 생성을 한 번에 처리하는 Windows 데스크톱 분석 도구입니다.

---

## 환경 세팅

### 요구사항

| 항목 | 버전 |
|---|---|
| Python | 3.10 이상 |
| OS | Windows 10 / 11 |

### 설치

```bash
git clone https://github.com/kimbjabgok/capev2_Analysis.git
cd capev2_Analysis
pip install -r requirements.txt
python main.py
```

### 의존성

```
requests
yara-python
tkinterdnd2
pyinstaller
python-dotenv
reportlab
pillow
```

### API 키 설정

실행 후 상단 메뉴 `도구 > 설정` 또는 첫 실행 시 하단 배너에서 입력합니다.

| 키 | 용도 |
|---|---|
| Groq API Key | AI 분석 (LLaMA 3.3 70B) |
| VirusTotal API Key | SHA256 기반 VT 조회 |

키는 `%APPDATA%\CAPEv2Analyzer\config.json`에 저장되며 배포 파일에는 포함되지 않습니다.

---

## 배포 (.exe 빌드)

```bash
.\build.bat
```

빌드 완료 시 `dist\CAPEv2_Analyzer.exe` 생성됩니다. Python 설치 없이 단독 실행 가능합니다.

---

## 주요 기능

### 리포트 로드
- `report.json` 파일 열기 (버튼 또는 드래그 앤 드롭)
- 멀티스레드 로딩으로 UI 블로킹 없음
- 로드 완료 시 판정 배너 자동 표시 (MALICIOUS / SUSPICIOUS / CLEAN)

### 분석 탭

| 탭 | 내용 |
|---|---|
| Overview | 판정 점수, 파일 해시, 패밀리, VirusTotal 조회 결과 |
| Signatures | 탐지된 시그니처 목록 (심각도별 색상 구분) |
| ATT&CK | MITRE ATT&CK TTP 매핑 테이블 |
| Behavior | 프로세스 API 콜 시퀀스 (화이트노이즈 필터 적용) |
| CAPE | Payload 추출 결과 및 YARA 매칭 |
| AI 분석 | Groq 기반 한국어 AI 분석 리포트 |

### 리포트 내보내기
- **HTML**: 5섹션 단일 파일, 인라인 CSS 다크 테마
- **PDF**: ReportLab 기반 5페이지 (커버 / IOC / Signatures / ATT&CK / AI Analysis), 한글 폰트(맑은 고딕) 자동 적용

---

## 탐지 룰

### 커스텀 시그니처 (`[CMR]` 태그)

`modules/signatures.py`에 정의된 행위 기반 탐지 룰입니다.

#### `[CMR] Download/Exec Chain`
LOLBin을 이용한 다운로드-실행 체인 탐지

| 탐지 항목 | 점수 |
|---|---|
| LOLBin 사용 (`powershell`, `certutil`, `mshta` 등) | +2 |
| 다운로드 힌트 (`http://`, `Invoke-WebRequest`, `-EncodedCommand` 등) | +3 |
| 의심 드롭 경로 (`\Temp\`, `\AppData\`, `\ProgramData\` 등) | +1 |
| 실행 가능 확장자 (`.exe`, `.dll`, `.ps1` 등) | +1 |

- 3점 미만 → 미탐지
- 3~4점 → `medium` / 5~6점 → `high` / 7점 이상 → `critical`
- TTP: `T1059`, `T1105`, `T1218`

#### `[CMR] Persistence Installed`
재부팅 후에도 유지되는 지속성 메커니즘 탐지

| 탐지 항목 | 점수 |
|---|---|
| 레지스트리 Run 키 / WinLogon 등록 | +3 |
| WMI Event Consumer 등록 | +3 |
| `schtasks /create`, `sc create`, `reg add` | +2 |
| Startup 폴더 등록 | +2 |
| 지속성 관련 확장자 (`.lnk`, `.vbs` 등) | +1 |

- 2점 미만 → 미탐지
- 2점 → `low` / 3~4점 → `medium` / 5점 이상 → `high`
- TTP: `T1547`, `T1053`, `T1543`, `T1546`

#### `[CMR] Sensitive Data Access`
브라우저 자격증명 및 암호화폐 지갑 접근 탐지

| 탐지 항목 | 점수 |
|---|---|
| Chrome / Edge / Brave 로그인 데이터, 쿠키 접근 | 건당 +2 |
| Exodus, Electrum 지갑 / `wallet.dat` 접근 | 건당 +3 |

- 2점 미만 → 미탐지
- 2~5점 → `high` / 6점 이상 → `critical`
- TTP: `T1555`, `T1539`, `T1552`

---

### YARA 룰 (`yara_rules/`)

CAPE Payload에 직접 적용되는 정적 패턴 탐지 룰입니다.

#### `RedLine_Stealer` (`redline.yar`)
RedLine / RecordBreaker 계열 인포스틸러 탐지

- 탐지 조건:
  - `Passwords`, `CreditCards`, `AutoFill`, `Login Data` 등 자격증명 관련 문자열 4개 이상
  - `recordbreaker` / `redline` 네트워크 식별자 + 자격증명 문자열 2개 이상
  - SQLite3 API + 자격증명 문자열 3개 이상

#### `Ransomware_Generic` (`ransomware.yar`)
랜섬웨어 일반 패턴 탐지

- 탐지 조건:
  - 랜섬 노트 문자열 (`YOUR FILES HAVE BEEN ENCRYPTED`, `DECRYPT`, `bitcoin` 등) 3개 이상
  - 암호화 확장자 (`.locked`, `.enc`, `.crypt` 등) + 랜섬 문자열 조합
  - `CryptEncrypt` / `BCryptEncrypt` API + 랜섬 문자열 조합
  - VSS 삭제 명령 (`delete shadows`, `resize shadowstorage`) 포함 시

#### `Ransomware_LockBit_Pattern` (`ransomware.yar`)
LockBit 계열 랜섬웨어 패턴 탐지

- 탐지 조건: `LockBit`, `.lockbit`, `Restore-My-Files` 등 2개 이상 매칭

---

### 화이트노이즈 필터 (`whitenoise_filter.json`)

분석 노이즈를 줄이기 위한 정상 Windows 행위 필터입니다. 보수적으로 운용합니다.

| 항목 | 내용 |
|---|---|
| `processes` (17개) | `svchost.exe`, `lsass.exe`, `explorer.exe` 등 핵심 시스템 프로세스 |
| `api_calls` (20개) | `NtQueryInformationProcess`, `RtlAllocateHeap`, `GetTickCount` 등 정상 NT/RTL 루틴 |
| `registry_keys` (2개) | `CurrentVersion`, `Nls` 경로 |
| `signature_names` (2개) | `antidbg_windows`, `antiemu_wine_reg` |

필터 항목 추가 시 `whitenoise_filter.json`을 직접 수정합니다.

---

## 프로젝트 구조

```
capev2_Analysis/
├── main.py                  # 진입점
├── build.bat                # PyInstaller 빌드 스크립트
├── CAPEv2_Analyzer.spec     # PyInstaller 빌드 설정
├── requirements.txt
├── whitenoise_filter.json   # 화이트노이즈 필터 설정
├── yara_rules/
│   ├── redline.yar
│   └── ransomware.yar
├── gui/
│   ├── app.py               # 메인 윈도우
│   ├── styles.py            # 다크 테마 색상/스타일
│   ├── tab_overview.py
│   ├── tab_signatures.py
│   ├── tab_attack.py
│   ├── tab_behavior.py
│   ├── tab_cape.py
│   └── tab_ai.py
└── modules/
    ├── parser.py            # report.json 파서
    ├── signatures.py        # [CMR] 커스텀 시그니처 엔진
    ├── yara_engine.py       # YARA 스캔 엔진
    ├── whitenoise.py        # 화이트노이즈 필터
    ├── ai_analysis.py       # Groq AI 분석
    ├── vt_api.py            # VirusTotal API
    ├── html_export.py       # HTML 리포트 생성
    └── pdf_export.py        # PDF 리포트 생성
```

---

## 라이선스

개인 학습 및 보안 연구 목적으로 제작되었습니다.
