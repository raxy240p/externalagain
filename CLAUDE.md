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
BYOVD swapped from NTIOLIBx64.sys (MSI Center) to RTCore64.sys (MSI Afterburner) —
the previous driver's phys-read handler had a process-identity gate that our
elevated-admin process couldn't cross. RTCore64's DACL admits admin directly and
its read primitive dispatches at IOCTL 0x80002048 with no arm sequence. Copy
RTCore64.sys to the machine-stable driver path GetDriverPath() prints on first
launch. Focus is now on ESP/triggerbot polish, ImGui menu behavior on R press,
and cache-thread tuning under RTCore64's per-unit dispatch model.
