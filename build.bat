@echo off
rem Build PE-Armor vx.xy (32-bit only) with msys2 mingw32.
rem Produces build\pearmor.exe (GUI) and build\pearmor-cli.exe (CLI).
rem Usage: build.bat        build both
rem        build.bat clean  remove build outputs
setlocal
set MSYS=C:\opt\scttools\compilers\msys64
set MINGW=%MSYS%\mingw32\bin
set PATH=%MINGW%;%PATH%

cd /d "%~dp0"

echo  #######################################################################
echo  #                                                                     #
echo  #   -=[                 PE-Armor vx.xy Builder                  ]=-   #
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

echo [1/4] resources...
pushd src
"%MINGW%\windres.exe" packer.rc -O coff -o packer_res.o
if errorlevel 1 goto err
"%MINGW%\windres.exe" -DPEARMOR_CLI packer.rc -O coff -o packer_cli_res.o
if errorlevel 1 goto err
popd

echo [2/4] GUI build...
"%MINGW%\gcc.exe" -m32 -mwindows -O2 -Wall -Wno-unused -c src\packer.c -o src\packer_gui.o
if errorlevel 1 goto err
"%MINGW%\gcc.exe" -m32 -mwindows -O2 -o build\pearmor.exe src\packer_gui.o src\packer_res.o src\aplib.lib ^
    -lcomctl32 -lcomdlg32 -lshell32 -lgdi32 -luser32 -lkernel32
if errorlevel 1 goto err

echo [3/4] CLI build...
"%MINGW%\gcc.exe" -m32 -mconsole -O2 -Wall -Wno-unused -DPEARMOR_CLI -c src\packer.c -o src\packer_cli.o
if errorlevel 1 goto err
"%MINGW%\gcc.exe" -m32 -mconsole -O2 -o build\pearmor-cli.exe src\packer_cli.o src\packer_cli_res.o src\aplib.lib ^
    -lkernel32
if errorlevel 1 goto err

echo [4/4] cleanup...
del src\packer_gui.o src\packer_cli.o src\packer_res.o src\packer_cli_res.o 2>nul
echo Built build\pearmor.exe and build\pearmor-cli.exe
exit /b 0

:clean
del /q build\pearmor.exe build\pearmor-cli.exe 2>nul
del /q src\packer_gui.o src\packer_cli.o src\packer_res.o src\packer_cli_res.o 2>nul
echo Cleaned.
exit /b 0

:err
popd 2>nul
echo Build failed.
exit /b 1
