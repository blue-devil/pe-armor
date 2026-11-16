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

* `build/packer.exe` - the 32-bit recreation produced by `build.bat`.
* `build/unpacked_packer.exe` - the unpacked original (see the tutorial).
* `src/` - a from-scratch C recreation of the packer with the original
  resources. `build.bat` (msys64 mingw32) writes `build\packer.exe`.
  (msys64 mingw32). Reproduces the vx.xx packing format exactly:
  aPLib-compressed sections, custom import obfuscation, TLS trampoline
  and the two-stage `.stub` shell; verified byte-level against the
  original packer's own output.

## Resources

* [CCG - China Cracking Group][01]
* [Exetools - PE-Armor vx.xx (Special Edition)][02]

[01]: https://www.exechina.com/
[02]: https://forum.exetools.com/showthread.php?t=21721
