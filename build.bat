@echo off
echo ===== CAPEv2 Report Analyzer Build =====
echo.

if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)

pip install -r requirements.txt

echo.
echo [*] PyInstaller build start...
pyinstaller CAPEv2_Analyzer.spec --clean --noconfirm

echo.
if exist dist\CAPEv2_Analyzer.exe (
    echo [OK] Build complete: dist\CAPEv2_Analyzer.exe
) else (
    echo [FAIL] Build failed - check error above
)
pause
