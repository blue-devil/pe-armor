# PE-Armor vx.xy (Developers' Edition)

PE-Armor historically created and distributed by [CCG][01]. I have unpacked
REPUBLIC's packed built, then reverse engineered and rewrite it with the same
functionality and GUI; then make a small contribution to the tool. And finally
open source it project.

The original PE-Armor first written in masm32 and only supports 32-bit binaries
to be packed.

REPUBLiC already made nice changes like support of windows 10/11 and
english interface.

His Changelog:

* English Interface.
* Packed file supports compatible with Windows 10/11.
* Support simple anti-dump, anti-debug, header protection.
* TLS-executable support (EXE and DLL)
* Redesigned interface.

I have added these contibutions:

* Strip debug sections option (on by default): drops the DWARF/COFF debug
  sections from the packed output, keeping the section VA layout intact
  for the Windows 11 ARM64 x86 loader.
* Compress resources option now really works: the original never wired
  the checkbox up and always stored `.rsrc` raw. This build compresses
  the whole resource section while keeping a minimal valid resource tree
  with the manifest visible for the loader (it reads `.rsrc` before any
  code runs); the stub restores the full section at load time.
* Command line version `pearmor-cli.exe` for batch and script usage; run
  `pearmor-cli` without arguments for the option list.

Read full [CHANGELOG](./CHANGELOG.md) for details.

## Build

> **IMPORTANT**: I am using MSYS2 for development in Windows platform.
> My build scripts are configured for using MSYS2. Do not forget that.

32-bit only, msys2 mingw32 toolchain:

```bash
build.bat        # or: sh build.sh  (from an msys2 shell)
build.bat clean  # remove build outputs
```

Produces `build/pearmor.exe` (GUI) and `build/pearmor-cli.exe` (CLI).

Example:

```bash
build/pearmor-cli.exe hello32.exe --pack-res --bak
```

## Resources

* [CCG - China Cracking Group][01]
* [Exetools - PE-Armor vx.xx (Special Edition)][02]
* [MSYS2 - Software Distribution and Building Platform for Windows][03]

[01]: https://www.exechina.com/
[02]: https://forum.exetools.com/showthread.php?t=21721
[03]: https://www.msys2.org/
