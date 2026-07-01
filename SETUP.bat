@echo off
REM ##############################################################################
REM Web Vulnerability Scanner - Automated Setup Script (Windows)
REM 
REM This script automates the entire setup process including:
REM - Creating a virtual environment
REM - Installing all dependencies
REM - Verifying the installation
REM - Creating necessary directories
REM
REM Usage: SETUP.bat
REM ##############################################################################

setlocal enabledelayedexpansion

REM Colors and formatting
set "RESET=[0m"
set "GREEN=[0;32m"
set "RED=[0;31m"
set "YELLOW=[1;33m"
set "BLUE=[0;34m"

echo.
echo [%BLUE%]========================================================[%RESET%]
echo [%BLUE%]  Web Vulnerability Scanner - Windows Setup[%RESET%]
echo [%BLUE%]========================================================[%RESET%]
echo.

REM Check if Python is installed
echo [%YELLOW%]i Checking Python installation...[%RESET%]
python --version >nul 2>&1
if errorlevel 1 (
    echo [%RED%]x Python not found. Please install Python 3.8 or higher.[%RESET%]
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set "PYTHON_VERSION=%%i"
echo [%GREEN%]v Python %PYTHON_VERSION% found[%RESET%]

REM Check if venv exists
if exist venv\ (
    echo [%YELLOW%]i Virtual environment 'venv' already exists[%RESET%]
    set /p RECREATE="Do you want to recreate it? (y/n): "
    if /i "!RECREATE!"=="y" (
        echo [%YELLOW%]i Removing existing virtual environment...[%RESET%]
        rmdir /s /q venv
    ) else (
        echo [%YELLOW%]i Using existing virtual environment[%RESET%]
    )
)

REM Create virtual environment
if not exist venv\ (
    echo [%YELLOW%]i Creating virtual environment...[%RESET%]
    python -m venv venv
    if errorlevel 1 (
        echo [%RED%]x Failed to create virtual environment[%RESET%]
        pause
        exit /b 1
    )
    echo [%GREEN%]v Virtual environment created[%RESET%]
)

REM Activate virtual environment
echo [%YELLOW%]i Activating virtual environment...[%RESET%]
call venv\Scripts\activate.bat
echo [%GREEN%]v Virtual environment activated[%RESET%]

REM Upgrade pip
echo [%YELLOW%]i Upgrading pip...[%RESET%]
python -m pip install --upgrade pip > nul 2>&1
echo [%GREEN%]v pip upgraded[%RESET%]

REM Install requirements
echo [%YELLOW%]i Installing dependencies from requirements.txt...[%RESET%]
if exist requirements.txt (
    pip install -r requirements.txt
    echo [%GREEN%]v Dependencies installed[%RESET%]
) else (
    echo [%RED%]x requirements.txt not found![%RESET%]
    pause
    exit /b 1
)

REM Create reports directory
echo [%YELLOW%]i Creating reports directory...[%RESET%]
if not exist reports\ mkdir reports
echo [%GREEN%]v Reports directory ready[%RESET%]

REM Verify installation
echo.
echo [%BLUE%]========================================================[%RESET%]
echo [%BLUE%]  Verification[%RESET%]
echo [%BLUE%]========================================================[%RESET%]
echo.

echo [%YELLOW%]i Verifying installed packages...[%RESET%]
set "PACKAGES_OK=true"

REM Check each package
python -c "import requests" >nul 2>&1
if errorlevel 1 (
    echo [%RED%]x requests missing[%RESET%]
    set "PACKAGES_OK=false"
) else (
    echo [%GREEN%]v requests installed[%RESET%]
)

python -c "import reportlab" >nul 2>&1
if errorlevel 1 (
    echo [%RED%]x reportlab missing[%RESET%]
    set "PACKAGES_OK=false"
) else (
    echo [%GREEN%]v reportlab installed[%RESET%]
)

python -c "import urllib3" >nul 2>&1
if errorlevel 1 (
    echo [%RED%]x urllib3 missing[%RESET%]
    set "PACKAGES_OK=false"
) else (
    echo [%GREEN%]v urllib3 installed[%RESET%]
)

REM Verify main script
if exist simple_main.py (
    echo [%GREEN%]v simple_main.py found[%RESET%]
) else (
    echo [%RED%]x simple_main.py not found![%RESET%]
    set "PACKAGES_OK=false"
)

REM Final status
echo.
echo [%BLUE%]========================================================[%RESET%]
echo [%BLUE%]  Setup Status[%RESET%]
echo [%BLUE%]========================================================[%RESET%]
echo.

if "%PACKAGES_OK%"=="true" (
    echo [%GREEN%]v All checks passed![%RESET%]
    echo.
    echo [%GREEN%]Setup Complete![%RESET%]
    echo.
    echo [%YELLOW%]Next steps:[%RESET%]
    echo 1. Activate virtual environment (next time you open terminal):
    echo    [%BLUE%]venv\Scripts\activate.bat[%RESET%]
    echo.
    echo 2. Run a scan:
    echo    [%BLUE%]python simple_main.py "http://target.com/page?param=value" --pdf[%RESET%]
    echo.
    echo 3. Check results:
    echo    [%BLUE%]dir reports\[%RESET%]
    echo.
    echo For help:
    echo    [%BLUE%]python simple_main.py -h[%RESET%]
    echo.
) else (
    echo [%RED%]Setup completed with errors. Please check the output above.[%RESET%]
    pause
    exit /b 1
)

pause
