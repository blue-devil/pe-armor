# Changelog

## [Unreleased]

## [vx.xy] - 2026-11-16

Developers' Edition, Blue DeviL // SCT. Recreation of the vx.xx build.

### Added

- Strip debug sections, on by default.
  - DWARF and COFF debug sections are dropped from the packed file
  - the section virtual addresses stay in place for the Windows 11 ARM64 x86 loader.
- Command-line packer `pearmor-cli.exe` for batch and script use.
- SCT icon on `pearmor.exe` (the file, the window, and the About box) and on `pearmor-cli.exe`.
- Windows version information on both executables.

### Changed

- Build outputs are `pearmor.exe` (GUI) and `pearmor-cli.exe` (CLI).

### Fixed

- Compress resources.
  - The option was never wired up, so `.rsrc` was always stored raw.
  - The section is now compressed, with a minimal resource tree left so the loader can read the manifest before any code runs. The stub restores the full section at load time.

## [vx.xx] - 2026-03-01

Special Edition, REPUBLiC. The day within March 2026 is not recorded; the about box dates this edition `2026.3`.

### Added

- English interface.
- Packed files that run on Windows 10 and Windows 11.
- Simple anti-dump, anti-debug, and header protection.
- TLS callback support for packed EXE and DLL files.

### Changed

- Redesigned interface.
