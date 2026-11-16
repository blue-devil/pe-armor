@echo off
rem Build PE-Armor vx.xx recreated packer (32-bit) with msys64 mingw32.
rem Produces build\packer.exe.
rem Usage: build.bat        build packer.exe
rem        build.bat clean  remove build artifacts
setlocal
set MSYS=C:\opt\scttools\compilers\msys64
set MINGW=%MSYS%\mingw32\bin
set PATH=%MINGW%;%PATH%

cd /d "%~dp0"

echo  #######################################################################
echo  #                                                                     #
echo  #   -=[                 PE-Armor vx.xx Builder                  ]=-   #
echo  #     _______ _______ _______                                         #
echo  #    ^|    ...^|    ...^|    ...^|  Author : Blue DeviL                   #
echo  #    ^|  _____^|    .__^|_   .._^|                                        #
echo  #    ^| ^|_____^|   .^|    ^|  .^|    Date   : 30/10/2026                   #
echo  #    ^|_____.:^|   :^|    ^|  :^|    WEB    : github.com/blue-devil        #
echo  #     _____^|:^|   :^|__  ^|  :^|                                          #
echo  #    ^|    .::^|   .:::^| ^|  :^|  --/   Freedom, doesn't come from   \--  #
echo  #    ^|_______^|_______^| ^|___^|  --\_     second-hand thoughts.    _/--  #
echo  #                                                                     #
echo  #######################################################################
echo.

if "%1"=="clean" goto clean

if not exist build mkdir build

echo [1/3] resources...
pushd src
"%MINGW%\windres.exe" packer.rc -O coff -o packer_res.o
if errorlevel 1 goto err
popd

echo [2/3] compile...
"%MINGW%\gcc.exe" -m32 -mwindows -O2 -Wall -Wno-unused -c src\packer.c -o src\packer.o
if errorlevel 1 goto err

echo [3/3] link...
"%MINGW%\gcc.exe" -m32 -mwindows -O2 -o build\packer.exe src\packer.o src\packer_res.o src\aplib.lib ^
    -lcomctl32 -lcomdlg32 -lshell32 -lgdi32 -luser32 -lkernel32
if errorlevel 1 goto err

del src\packer.o src\packer_res.o 2>nul
echo Built build\packer.exe
exit /b 0

:clean
del /q build\packer.exe 2>nul
del /q src\packer.o src\packer_res.o 2>nul
echo Cleaned.
exit /b 0

:err
popd 2>nul
echo Build failed.
exit /b 1
