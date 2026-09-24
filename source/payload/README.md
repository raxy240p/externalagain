# payload — manual-mapped kernel reader

Minimal payload that gets manual-mapped into kernel by TheCruZ/kdmapper.
Exposes one named section (`Global\Xh7Km2p9Qr4tZ8`) and services read /
write / attach-pid requests via a spin-poll protocol. No driver object,
no device, no IOCTL — see `payload_shared.h` for the wire format.

## Build (Windows only, WDK required)

Prereqs: Visual Studio 2022 Community/Pro, Windows Driver Kit (WDK) 10
matching your Windows SDK version. Install via VS Installer → Individual
Components → "Windows 11 SDK" + "Windows Driver Kit".

```
cd source\payload
```

Create a KMDF empty driver project in VS: File → New → Project → Kernel
Mode Driver, Empty (KMDF). Add `payload.c` and `payload_shared.h` to the
project. Set:

- Configuration Type: Driver (.sys)
- Platform: x64
- Target OS Version: Windows 10 or later
- Target Platform: Desktop
- Runtime Library: `/MT` (no CRT dependency)
- C Language Standard: C17
- Disable Warnings-as-Errors (some ntifs.h warnings are cosmetic)
- Remove `_KMDF_` from preprocessor defines (we're using raw NT, not KMDF)
- Add `_NO_CRT_STDIO_INLINE` to preprocessor defines
- Linker → Ignore Specific Libraries: `WdfDriverEntry.lib`, `WdfLdr.lib`
- Linker → Additional Dependencies: `ntoskrnl.lib;$(DDK_LIB_PATH)ntoskrnl.lib`
- Driver Settings → Sign Mode: `Off` (we manual-map, no signing needed)

Build → x64 Release. Output: `payload.sys` (~10–20 KB).

## Alternative: raw command-line build

If you have the WDK installed:

```powershell
$env:INCLUDE += ";C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\km;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\km\crt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared"
$env:LIB     += ";C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\km\x64"

cl.exe /kernel /GS- /Zl /c payload.c /Fopayload.obj
link.exe /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB /MACHINE:X64 payload.obj ntoskrnl.lib /OUT:payload.sys
```

(Adjust WDK version paths per your install.)

## Deploying

Copy `payload.sys` next to the mapper binary. See `source/mapper/README.md`
for the load flow. The cheat executable auto-invokes the mapper on
startup if the shared section isn't already open (implying payload isn't
loaded).

## Verifying it loaded

```powershell
# From an elevated PowerShell:
$h = [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting("Global\Xh7Km2p9Qr4tZ8")
$h.Dispose(); Write-Host "payload alive"
```

If that opens without exception, the shared section is live and the
payload is running. If it throws `FileNotFoundException`, the mapper
either didn't run or the payload crashed (check `!analyze -v` in windbg
or the last bugcheck code).

## Uninstall / cleanup

The payload lives until reboot. To retire it early, the cheat writes
`PAYLOAD_STATE_SHUTDOWN` into `state` — the reader thread exits, tears
down the section, and terminates. Nothing to sc.exe delete; the payload
was never a registered service.
