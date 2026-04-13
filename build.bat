@echo off
echo ===== CAPEv2 Report Analyzer Build =====
echo.

if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)

pip install -r requirements.txt

echo.
echo [*] PyInstaller 빌드 시작...
pyinstaller CAPEv2_Analyzer.spec --clean --noconfirm

echo.
if exist dist\CAPEv2_Analyzer.exe (
    echo [OK] 빌드 완료: dist\CAPEv2_Analyzer.exe
) else (
    echo [FAIL] 빌드 실패 - 위 오류 메시지 확인
)
pause
