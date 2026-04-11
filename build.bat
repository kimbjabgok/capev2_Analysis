@echo off
echo ===== CAPEv2 Report Analyzer Build =====
echo.

REM 가상환경 활성화 (있으면)
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)

REM 의존성 설치
pip install -r requirements.txt

echo.
echo [*] PyInstaller 빌드 시작...

pyinstaller ^
  --onefile ^
  --windowed ^
  --name "CAPEv2_Analyzer" ^
  --add-data "yara_rules;yara_rules" ^
  --add-data "whitenoise_filter.json;." ^
  --hidden-import tkinterdnd2 ^
  --hidden-import yara ^
  main.py

echo.
if exist dist\CAPEv2_Analyzer.exe (
    echo [OK] 빌드 완료: dist\CAPEv2_Analyzer.exe
) else (
    echo [FAIL] 빌드 실패 — 위 오류 메시지 확인
)
pause
