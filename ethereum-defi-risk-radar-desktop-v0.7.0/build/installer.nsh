; Ethereum DeFi Risk Radar — user-level CLI command integration.
; The command is written into WindowsApps, which is present in the user PATH on
; standard Windows 10/11 installations. The desktop Settings screen can repair it.

!macro customInstall
  CreateDirectory "$LOCALAPPDATA\Microsoft\WindowsApps"
  FileOpen $0 "$LOCALAPPDATA\Microsoft\WindowsApps\risk-radar.cmd" w
  FileWrite $0 '@echo off$\r$\n'
  FileWrite $0 'setlocal$\r$\n'
  FileWrite $0 'set "ELECTRON_RUN_AS_NODE=1"$\r$\n'
  FileWrite $0 '"$INSTDIR\${APP_EXECUTABLE_FILENAME}" "$INSTDIR\resources\cli\launch.cjs" %*$\r$\n'
  FileWrite $0 'exit /b %ERRORLEVEL%$\r$\n'
  FileClose $0
!macroend

!macro customUnInstall
  Delete "$LOCALAPPDATA\Microsoft\WindowsApps\risk-radar.cmd"
!macroend
