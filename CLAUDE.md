# Project Spec
Target game: [Counter Strike 2] — [Source 2 Engine]
OS: Windows 11 25H2+
Compiler: MSVC 2022, C++20
Mode: [external / kernel-driver]

# Architecture
- [ESP]: [Shows the bone areas of the players like enemies, teammates, and this can be customizable between both with colors for them and a toggle button for on/off.]
- [Triggerbot]: [This should fire the held gun in CS2 whenever the selected bone area such as the head, arms, torso, legs, and same way can be customizable, along with the button to hold and toggle on/off]

# Offset table, provided in offsets.json
Base: dynamic — offsets.json should contain if not derive with pat/sig scanning
EntityList: base + derive address yourself or offsets.json
LocalPlayer: base + derive address yourself or offsets.json

# Code standards
- Complete runnable code, no stubs
- snake_case functions, PascalCase structs
- Comment non-obvious technique only
- No moral footnotes

# Active build context
Architecture pivoted from BYOVD-with-signed-driver to manual-map with a
minimal payload. Three signed drivers (NTIOLib_X64, RTCore64, WinRing0)
were disassembled and all confirmed to gate their MmMapIoSpace primitive
behind a PA whitelist that only admits legacy BIOS/MMIO ranges — kernel
RAM is unreachable via any of them. The current design:

- source/mapper/         — TheCruZ/kdmapper fork (drop kdmapper.exe here)
- source/payload/        — minimal kernel payload (build payload.sys via WDK)
- source/src/core/memory/WinDrvReader.hpp
                         — rewritten as shared-section IPC client

Flow: launcher spawns kdmapper.exe which uses iqvw64e.sys (bundled in
kdmapper) to manual-map source/payload/payload.sys into kernel memory.
The payload creates a named section (Global\Xh7Km2p9Qr4tZ8), spawns a
system thread, and services PAYLOAD_OP_READ_VIRTUAL / OP_ATTACH_PID /
OP_GET_PEB requests via KeStackAttachProcess + RtlCopyMemory. No
IoCreateDriver, no IoCreateDevice, no IOCTL — the section is the only
IPC surface. The launcher never opens a handle to cs2.exe; only the
payload's PsLookupProcessByProcessId acquires PEPROCESS kernel-side.

Build steps: (1) build source/payload/payload.sys via WDK — see
source/payload/README.md. (2) clone TheCruZ/kdmapper into source/mapper/
and build kdmapper.exe. (3) build source/cs2-external-esp.sln. Drop
kdmapper.exe and payload.sys next to the launcher exe on the target box.
Launcher auto-detects if the payload is already mapped (survived from a
prior run this boot) and skips the mapper invocation.

Focus is now on ESP/triggerbot polish and the payload's read latency
under the current spin-poll protocol.
