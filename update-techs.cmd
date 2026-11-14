@echo off
REM TechScope — refresh the technology fingerprint dataset from upstream.
REM Run by the scheduled task "TechScope-UpdateData", or double-click to run now.
setlocal
REM Resolve this script's own folder so the task is portable.
set "EXT=%~dp0"
set "NODE=C:\Program Files\nodejs\node.exe"
if not exist "%NODE%" set "NODE=node"
echo [%date% %time%] starting fingerprint update>> "%EXT%update-techs.log"
"%NODE%" "%EXT%build-tech.mjs" --fetch >> "%EXT%update-techs.log" 2>&1
echo [%date% %time%] finished (exit %errorlevel%)>> "%EXT%update-techs.log"
endlocal
