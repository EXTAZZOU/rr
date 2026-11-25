@echo off
setlocal
rem Release build: enforces license + HWID authorization.
rem The dev build (build_anti_tchoy.bat) skips auth so you can use your own
rem overlay without touching the server.
rem
rem Before using this script:
rem   1. Deploy auth-server/ to a reachable HTTPS endpoint.
rem   2. Edit auth\at_auth.h and set AT_AUTH_URL to that endpoint.
rem   3. Run this script. Output: antitchoy.exe with auth enforced.
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

set "WV2=%~dp0..\2_src_port\WebView2SDK"
if not exist "%WV2%\include\WebView2.h" ( echo [ERROR] WebView2 SDK missing & pause & exit /b 1 )

set "CFLAGS=/nologo /O2 /D_CRT_SECURE_NO_WARNINGS /W3 /MT /DAT_AUTH_ENFORCE /DAT_PROD_BUILD"
set "CXXFLAGS=/nologo /O2 /D_CRT_SECURE_NO_WARNINGS /W3 /MT /EHsc /DAT_AUTH_ENFORCE /DAT_PROD_BUILD"

echo [1/9] rr_esp.c
cl %CFLAGS% /c rr_esp.c /Fo:rr_esp.obj || goto fail
echo [2/9] rr_game.c
cl %CFLAGS% /c rr_game.c /Fo:rr_game.obj || goto fail
echo [3/9] rr_mem.c
cl %CFLAGS% /c rr_mem.c /Fo:rr_mem.obj || goto fail
echo [4/9] rr_unity.c
cl %CFLAGS% /c rr_unity.c /Fo:rr_unity.obj || goto fail
echo [5/9] rr_chain.c
cl %CFLAGS% /c rr_chain.c /Fo:rr_chain.obj || goto fail
echo [6/9] rr_draw.c + rr_aim.c + los
cl %CFLAGS% /c rr_draw.c /Fo:rr_draw.obj || goto fail
cl %CFLAGS% /c rr_aim.c /Fo:rr_aim.obj || goto fail
cl %CFLAGS% /c rr_los_geom.c /Fo:rr_los_geom.obj || goto fail
cl %CFLAGS% /c rr_los_capture.c /Fo:rr_los_capture.obj || goto fail
cl %CFLAGS% /c rr_los_runtime.c /Fo:rr_los_runtime.obj || goto fail
cl %CFLAGS% /c rr_los.c /Fo:rr_los.obj || goto fail
echo [7/9] gpu.cpp + menu_webview.cpp
cl %CXXFLAGS% /c /I "%WV2%\include" gpu.cpp /Fo:gpu.obj || goto fail
cl %CXXFLAGS% /c /I "%WV2%\include" menu_webview.cpp /Fo:menu_webview.obj || goto fail
echo [8/9] scan + spawn + auth + norecoil + payload
cl %CFLAGS% /c rr_spawn.c /Fo:rr_spawn.obj || goto fail
cl %CFLAGS% /c rr_nodescan.c /Fo:rr_nodescan.obj || goto fail
cl %CFLAGS% /c rr_classscan.c /Fo:rr_classscan.obj || goto fail
cl %CFLAGS% /c rr_find.c /Fo:rr_find.obj || goto fail
cl %CFLAGS% /c rr_norecoil.c /Fo:rr_norecoil.obj || goto fail
cl %CFLAGS% /c auth\at_auth.c /Fo:at_auth.obj || goto fail
cl %CFLAGS% /c auth\at_payload.c /Fo:at_payload.obj || goto fail
echo [9/9] resources + link
rc /nologo /fo app.res app.rc || goto fail
link /nologo /SUBSYSTEM:WINDOWS /MACHINE:X64 /OUT:antitchoy.exe ^
  rr_esp.obj rr_game.obj rr_mem.obj rr_unity.obj rr_chain.obj rr_draw.obj rr_aim.obj ^
  rr_los_geom.obj rr_los_capture.obj rr_los_runtime.obj rr_los.obj rr_spawn.obj ^
 rr_nodescan.obj rr_classscan.obj rr_find.obj rr_norecoil.obj at_auth.obj at_payload.obj ^
  gpu.obj menu_webview.obj app.res ^
  kernel32.lib user32.lib gdi32.lib comctl32.lib advapi32.lib ole32.lib oleaut32.lib uuid.lib shell32.lib ws2_32.lib ^
  d3d11.lib dxgi.lib d2d1.lib dwrite.lib dcomp.lib d3dcompiler.lib dbghelp.lib ^
  winhttp.lib crypt32.lib bcrypt.lib iphlpapi.lib ^
  /LIBPATH:"%WV2%\lib\x64" WebView2Loader.dll.lib || goto fail

if not exist WebView2Loader.dll copy /Y "%WV2%\lib\x64\WebView2Loader.dll" . >nul

echo.
echo RELEASE_OK  -^>  antitchoy.exe  (auth enforced)
exit /b 0

:fail
echo RELEASE_FAIL
exit /b 1
