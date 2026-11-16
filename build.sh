#!/bin/sh
# Build PE-Armor vx.xy (32-bit only) with msys2 mingw32.
# Produces build/pearmor.exe (GUI) and build/pearmor-cli.exe (CLI).
set -e
cd "$(dirname "$0")"
MSYS=/c/opt/scttools/compilers/msys64
MINGW=$MSYS/mingw32/bin
export PATH=$MINGW:$PATH

echo " #######################################################################"
echo " #                                                                     #"
echo " #   -=[                 PE-Armor vx.xy Builder                  ]=-   #"
echo " #     _______ _______ _______                                         #"
echo " #    |    ...|    ...|    ...|  Author : Blue DeviL                   #"
echo " #    |  _____|    .__|_   .._|                                        #"
echo " #    | |_____|   .|    |  .|    Date   : 30/10/2026                   #"
echo " #    |_____.:|   :|    |  :|    WEB    : github.com/blue-devil        #"
echo " #     _____|:|   :|__  |  :|                                          #"
echo " #    |    .::|   .:::| |  :|  --/   Freedom, doesn't come from   \--  #"
echo " #    |_______|_______| |___|  --\_     second-hand thoughts.    _/--  #"
echo " #                                                                     #"
echo " #######################################################################"
echo ""

if [ "$1" = "clean" ]; then
    rm -f build/pearmor.exe build/pearmor-cli.exe src/packer_gui.o src/packer_cli.o src/packer_res.o src/packer_cli_res.o
    echo Cleaned.
    exit 0
fi

mkdir -p build

echo [1/4] resources...
( cd src && windres packer.rc -O coff -o packer_res.o )
( cd src && windres -DPEARMOR_CLI packer.rc -O coff -o packer_cli_res.o )

echo [2/4] GUI build...
gcc -m32 -mwindows -O2 -Wall -Wno-unused -c src/packer.c -o src/packer_gui.o
gcc -m32 -mwindows -O2 -o build/pearmor.exe src/packer_gui.o src/packer_res.o src/aplib.lib \
    -lcomctl32 -lcomdlg32 -lshell32 -lgdi32 -luser32 -lkernel32

echo [3/4] CLI build...
gcc -m32 -mconsole -O2 -Wall -Wno-unused -DPEARMOR_CLI -c src/packer.c -o src/packer_cli.o
gcc -m32 -mconsole -O2 -o build/pearmor-cli.exe src/packer_cli.o src/packer_cli_res.o src/aplib.lib -lkernel32

echo [4/4] cleanup...
rm -f src/packer_gui.o src/packer_cli.o src/packer_res.o src/packer_cli_res.o
echo "Built build/pearmor.exe and build/pearmor-cli.exe"
