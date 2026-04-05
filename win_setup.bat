@echo off
chcp 65001 >nul
echo === Secure Tunnel Client Setup ===

echo [1/2] Installing Python packages...
python -m pip install --upgrade pip --quiet
python -m pip install cryptography pillow textual pyreadline3 --quiet
echo       Done.

echo [2/2] Installing Tor...
where tor >nul 2>&1 && (
    echo       Already installed.
    goto :tor_done
)
winget --version >nul 2>&1 && (
    winget install --id TorProject.TorBrowser --silent --accept-package-agreements --accept-source-agreements
    echo       Tor Browser installed (includes tor.exe).
    goto :tor_done
)
choco --version >nul 2>&1 && (
    choco install tor -y
    goto :tor_done
)
echo       Could not auto-install Tor. Install manually from https://www.torproject.org if needed.
:tor_done

echo.
echo Setup complete. Start with:
echo   python tui.py
echo   python client.py --relay ^<ip^> --secret ^<key^> --name ^<you^> --knock-ports 1000,2000,3000
pause
