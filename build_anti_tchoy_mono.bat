@echo off
setlocal
rem Build the ANTI-TCHOY all-in-one launcher.
rem Prerequisite: run build_anti_tchoy_release.bat first so antitchoy.exe
rem (auth-enforced overlay) exists in this folder.
rem
rem Output: ANTI-TCHOY.exe here, copied to ..\ANTI-TCHOY_v1.0\ANTI-TCHOY.exe.
cd /d "%~dp0"

set "VS="
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\18\Community"
    "C:\Program Files\Microsoft Visual Studio\18\Professional"
    "C:\Program Files\Microsoft Visual Studio\2022\Community"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional"
) do if not defined VS if exist "%%~P\VC\Auxiliary\Build\vcvars64.bat" set "VS=%%~P"
if not defined VS ( echo [ERROR] vcvars64.bat not found & pause & exit /b 1 )
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo VCVARS_FAIL & exit /b 1 )

rem Payloads must exist.
for %%F in ("Logit.exe" "..\1_run\kd2.exe" "..\1_run\kernel-mode.sys" "..\1_run\WebView2Loader.dll") do (
    if not exist %%F (
        echo [ERROR] missing payload: %%~F
        echo         Run build_anti_tchoy_release.bat first if Logit.exe is missing.
        pause
        exit /b 1
    )
)

set "CFLAGS=/nologo /O2 /W3 /MT /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS /DAT_PROD_BUILD"

echo [1/3] resources
rc /nologo /fo aio_launcher.res aio_launcher.rc || goto fail
echo [2/3] compile launcher
cl %CFLAGS% /c aio_launcher.c /Fo:aio_launcher.obj || goto fail
echo [3/3] link
link /nologo /SUBSYSTEM:WINDOWS /MACHINE:X64 /OUT:Logit-launcher.exe ^
  /MANIFEST:EMBED /MANIFESTINPUT:aio.manifest ^
  /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'" ^
  aio_launcher.obj aio_launcher.res ^
  user32.lib gdi32.lib advapi32.lib comctl32.lib bcrypt.lib || goto fail

if not exist "..\Logit_v1.0" mkdir "..\Logit_v1.0"
copy /Y Logit-launcher.exe "..\Logit_v1.0\Logit.exe" >nul

echo.
echo MONO_OK  -^>  Logit.exe  (copied to ..\Logit_v1.0)
exit /b 0

:fail
echo MONO_FAIL
exit /b 1
