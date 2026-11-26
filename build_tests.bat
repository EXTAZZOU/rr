@echo off
setlocal
rem Harnais console des fonctions pures de couleur (br_color, alpha_scale).
rem Zero dependance D3D / WebView2 / jeu : compile et tourne hors du process
rem de jeu, utilisable meme sans acces runtime (ex : ban actif sur la cible).
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

rem /O1 au lieu de /O2 pour laisser alpha_scale/br_color inlinables mais lisibles
rem au debugger. /MT aligne sur le runtime des builds principaux pour eviter les
rem mismatches d'alloc. Pas de /DNDEBUG : les assertions du test doivent rester
rem actives meme si un jour on en ajoute via <assert.h>.
set "TESTCFLAGS=/nologo /O1 /W3 /MT"
set "TESTCXXFLAGS=/nologo /O1 /W3 /MT /EHsc"

echo [1/3] br_color.c
rem Nom d'objet distinct (br_color_test.obj) pour ne pas ecraser br_color.obj
rem du build principal si les deux tournent dans le meme dossier.
cl %TESTCFLAGS% /c br_color.c /Fo:br_color_test.obj || goto fail

echo [2/3] test_br_color.cpp
cl %TESTCXXFLAGS% /c test_br_color.cpp /Fo:test_br_color.obj || goto fail

echo [3/3] link + run
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X64 /OUT:test_br_color.exe ^
  br_color_test.obj test_br_color.obj kernel32.lib || goto fail
.\test_br_color.exe
if errorlevel 1 goto fail
echo TESTS_OK
exit /b 0

:fail
echo TESTS_FAIL
exit /b 1
