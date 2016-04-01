; MUI 1.67 compatible ------
!include "MUI.nsh"

!define PRODUCT_NAME "tbootxm_bootdriver"
!define PRODUCT_VERSION "1.0"
!define PRODUCT_PUBLISHER "Intel Corporation"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; License page
;!insertmacro MUI_PAGE_LICENSE ""
; Components page
!insertmacro MUI_PAGE_COMPONENTS
; Directory page
;!insertmacro MUI_PAGE_DIRECTORY
; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
!define MUI_FINISHPAGE_NOAUTOCLOSE
;!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
;!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "French"
!insertmacro MUI_LANGUAGE "German"

; MUI end ------

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "tbootxm_bootdriver-setup.exe"
InstallDir "$PROGRAMFILES\Intel\tbootxm"
ShowInstDetails show
ShowUnInstDetails show

Function .onInit
  !insertmacro MUI_LANGDLL_DISPLAY
FunctionEnd

Section "tbootxm_bootdriver" SEC01
  SetOverwrite try
  SetOutPath "$INSTDIR"
  File ".\Win7Debug\tbootxm_bootdriver Package\tbootxm_bootdriver.cat"
  File ".\Win7Debug\tbootxm_bootdriver Package\tbootxm_bootdriver.inf"
  File ".\Win7Debug\tbootxm_bootdriver Package\tbootxm_bootdriver.sys"
SectionEnd

Section -Post
  WriteUninstaller "$INSTDIR\uninst.exe"
SectionEnd

Section -InstallDriver
  nsExec::Exec 'C:\Windows\System32\RUNDLL32.EXE C:\Windows\System32\SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 $INSTDIR\tbootxm_bootdriver.inf'
SectionEnd

; Section descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC01} "Installs the tbootxm_bootdriver"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function un.onUninstSuccess
  HideWindow
  MessageBox MB_ICONINFORMATION|MB_OK "$(^Name) was successfully removed from your computer."
FunctionEnd

Function un.onInit
  MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove $(^Name) and all of its components?" IDYES +2
  Abort
FunctionEnd

Section Uninstall
  nsExec::Exec 'C:\Windows\System32\RUNDLL32.EXE C:\Windows\System32\SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 $INSTDIR\tbootxm_bootdriver.inf'

  Delete "$INSTDIR\tbootxm_bootdriver.cat"
  Delete "$INSTDIR\tbootxm_bootdriver.inf"
  Delete "$INSTDIR\tbootxm_bootdriver.sys"
  RMDir "$INSTDIR"
  SetAutoClose true
SectionEnd