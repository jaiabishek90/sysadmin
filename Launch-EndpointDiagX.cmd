@echo off
REM ===========================================================================
REM  Sys@dmin v4 launcher
REM  Right-click this file  ->  "Run as administrator"  for full capability.
REM  (The script also self-elevates via UAC if you just double-click it.)
REM ===========================================================================
setlocal
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

if not exist "%~dp0EndpointDiagX.ps1" (
  echo [ERROR] EndpointDiagX.ps1 not found next to this launcher.
  pause & exit /b 1
)
if not exist "%~dp0DiagEngine.ps1" (
  echo [ERROR] DiagEngine.ps1 not found next to this launcher.
  pause & exit /b 1
)
if not exist "%~dp0KnowledgeBase.json" (
  echo [WARN] KnowledgeBase.json not found - resolutions fall back to generic triage.
)

echo Starting Sys@dmin ...
"%PS%" -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0EndpointDiagX.ps1" %*
if errorlevel 1 (
  echo.
  echo Sys@dmin exited with an error. Re-run with the console visible:
  echo    powershell -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0EndpointDiagX.ps1"
  pause
)
endlocal
