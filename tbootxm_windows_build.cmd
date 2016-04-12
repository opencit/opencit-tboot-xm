@echo off
setlocal enabledelayedexpansion

set me=%~n0
set pwd=%~dp0

set makensis="C:\NSIS\makensis.exe"

IF "%1"=="" (
  call:print_help
) ELSE IF "%2"=="" (
  call:print_help
) ELSE (
  call:tbootxm_install %1 %2
)
GOTO:EOF

:tbootxm_install
  echo. Creating tbootxm_bootdriver installer.... %1 %2
  call:tbootxm_build %1 %2
  call:tbootxm_install
GOTO:EOF

:tbootxm_build
  echo. Building tbootxm_bootdriver.... %1 %2
  cd
  call tbootxm_bootdriver_build.cmd %1 %2
  IF NOT %ERRORLEVEL% EQU 0 (
    echo. %me%: tbootxm build failed
	EXIT /b %ERRORLEVEL%
  )
GOTO:EOF

:tbootxm_install
  echo. Creating tbootxm_bootdriver installer....
  cd
  call %makensis% tbootxm_bootdriver_installer.nsi
  IF NOT %ERRORLEVEL% EQU 0 (
    echo. %me%: tbootxm install failed
	EXIT /b %ERRORLEVEL%
  )
GOTO:EOF

:print_help
  echo. "Usage: $0 Platform Configuration"
GOTO:EOF

endlocal