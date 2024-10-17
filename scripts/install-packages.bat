@ECHO OFF
CD /D "%~dp0"

vcpkg --version > nul

IF NOT %ERRORLEVEL% == 0 (
    ECHO Failed to get vcpkg version, please check if it's installed and addet to the System Environment Variables.
    EXIT /B %ERRORLEVEL%
)

vcpkg install zlib:x64-windows-static openssl:x64-windows-static

IF NOT %ERRORLEVEL% == 0 (
    ECHO vcpkg failed to install required packages.
    EXIT /B %ERRORLEVEL%
)

EXIT /B 0