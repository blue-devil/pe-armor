# PE-Armor vx.xx (Special Edition)

PE-Armor historically created and distributed by [CCG][01]. This built
is created by `REPUBLiC` an exetools forum user. He didn't share
source code unfortunately and his packer is also packed/protected.

He made nice changes like support of windows 10/11 and english interface.

Changelog:

* English Interface.
* Packed file supports compatible with Windows 10/11.
* Support simple anti-dump, anti-debug, header protection.
* TLS-executable support (EXE and DLL)
* Redesigned interface.

## This repository

So I first unpacked this `packer.exe - vx.xx` then reverse engineered it
and rewrite it. So this repo contains not REPUBliC's original sources
intead they are reverse engineered by me.

Because i prefer MSYS2 environment in Windows, my build script builds the
project by mingw-32.

## Resources

* [CCG - China Cracking Group][01]
* [Exetools - PE-Armor vx.xx (Special Edition)][02]
* [MSYS - Software Distribution and Building Platform for Windows][03]

[01]: https://www.exechina.com/
[02]: https://forum.exetools.com/showthread.php?t=21721
[03]: https://www.msys2.org/
