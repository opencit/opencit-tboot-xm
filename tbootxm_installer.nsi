; MUI 1.67 compatible ------
!include "MUI.nsh"
!include "x64.nsh"

!define PRODUCT_NAME "tbootxm"
!define PRODUCT_VERSION "1.0"
!define PRODUCT_PUBLISHER "Intel Corporation"
!define PRODUCT_DIR_REGKEY "SYSTEM\CurrentControlSet\services\${PRODUCT_NAME}"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; MUI end ------

Name "${PRODUCT_NAME}"
OutFile "tbootxm-setup.exe"
InstallDir "$PROGRAMFILES\Intel\tbootxm"
ShowInstDetails show
ShowUnInstDetails show

; ------------------------------------------------------------------
; ***************************** PAGES ******************************
; ------------------------------------------------------------------

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; License page
;!insertmacro MUI_PAGE_LICENSE ""
; Components page
;!insertmacro MUI_PAGE_COMPONENTS
; Directory page
!define MUI_PAGE_CUSTOMFUNCTION_SHOW DirectoryPageShow
!insertmacro MUI_PAGE_DIRECTORY
; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
!define MUI_FINISHPAGE_NOAUTOCLOSE
;!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
;!define MUI_FINISHPAGE_SHOWREADME ""
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"
; -------------------------------------------------------------------------
; ***************************** END OF PAGES ******************************
; -------------------------------------------------------------------------

; ----------------------------------------------------------------------------------
; *************************** SECTION FOR INSTALLING *******************************
; ----------------------------------------------------------------------------------

Section Install
  SetOverwrite ifnewer
  SetOutPath "$INSTDIR\bin"
  File ".\tbootxm_bootdriver\signed\tbootxm_bootdriver.cat"
  File ".\tbootxm_bootdriver\signed\tbootxm_bootdriver.inf"
  File ".\tbootxm_bootdriver\signed\tbootxm_bootdriver.sys"
  File ".\imvm\bin\verifier.exe"
SectionEnd

Section Post
  WriteUninstaller "$INSTDIR\uninst.exe"
SectionEnd

Section InstallDriver
  # Install tbootxm driver and create tbootxm service
  ${If} ${RunningX64}
    ${DisableX64FSRedirection}
  ${EndIf}
  nsExec::Exec 'C:\Windows\System32\RUNDLL32.EXE C:\Windows\System32\SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 $INSTDIR\bin\tbootxm_bootdriver.inf'
SectionEnd

; ----------------------------------------------------------------------------------
; ************************** SECTION FOR UNINSTALLING ******************************
; ----------------------------------------------------------------------------------

Section Uninstall
  # Uninstall tbootxm driver and remove tbootxm service
  ${If} ${RunningX64}
    ${DisableX64FSRedirection}
  ${EndIf}
  nsExec::Exec 'C:\Windows\System32\RUNDLL32.EXE C:\Windows\System32\SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 $INSTDIR\bin\tbootxm_bootdriver.inf'

  Delete "$INSTDIR\uninst.exe"
  Delete "$INSTDIR\bin\verifier.exe"
  Delete "$INSTDIR\bin\tbootxm_bootdriver.cat"
  Delete "$INSTDIR\bin\tbootxm_bootdriver.inf"
  Delete "$INSTDIR\bin\tbootxm_bootdriver.sys"

  RMDir "$INSTDIR\bin"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  SetAutoClose true
SectionEnd
; ----------------------------------------------------------------------------------
; ********************* END OF INSTALL/UNINSTALL SECTIONS **************************
; ----------------------------------------------------------------------------------

; ----------------------------------------------------------
; ********************* FUNCTIONS **************************
; ----------------------------------------------------------

Function .onInit
FunctionEnd

Function un.onInit
;  MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove $(^Name) and all of its components?" IDYES +2
;  Abort
FunctionEnd

Function un.onUninstSuccess
;  HideWindow
;  MessageBox MB_ICONINFORMATION|MB_OK "$(^Name) was successfully removed from your computer."
FunctionEnd

Function DirectoryPageShow
	FindWindow $R0 "#32770" "" $HWNDPARENT
	GetDlgItem $R1 $R0 1019
	EnableWindow $R1 0
	GetDlgItem $R1 $R0 1001
	EnableWindow $R1 0
FunctionEnd
; ----------------------------------------------------------
; ****************** END OF FUNCTIONS **********************
; ----------------------------------------------------------