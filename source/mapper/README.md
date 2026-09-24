# mapper — kdmapper fork

We use TheCruZ's kdmapper for the initial payload load. It exploits the
Intel Ethernet driver (iqvw64e.sys, CVE-2015-2291) to gain kernel primitive,
allocates NonPagedPool for the payload, fixes imports/relocations, calls
its entry point, then unloads its own service so nothing persists in SCM.

## Getting the source

```
cd source/mapper
git clone https://github.com/TheCruZ/kdmapper.git .
```

Build in Visual Studio 2022 (`kdmapper.sln`), x64 / Release. Output:
`kdmapper.exe`. The repo ships `intel_driver_resource.hpp` with iqvw64e's
bytes embedded, so nothing else on disk is needed at load time.

## Runtime layout

The cheat executable launches the mapper on startup:

```
cs2-external-esp.exe            (our launcher)
├── source/mapper/kdmapper.exe  (spawned as a child process)
└── source/payload/payload.sys  (passed as kdmapper arg)
```

Once `kdmapper` exits with status 0, the payload's system thread is
running in kernel and the `Global\Xh7Km2p9Qr4tZ8` section is live. Our
launcher then opens the section and drives it via `WinDrvReader::Get()`.

If the section is already open when the launcher starts (payload from a
previous cheat run this boot), the mapper invocation is skipped — the
payload survives across launcher restarts within one boot.

## Optional: build kdmapper into a static lib

For a single-binary distribution, add kdmapper's sources into
`source/mapper/lib/` and expose a `bool kdmapper_load(const char*
payload_path)` entry point that our launcher calls directly instead of
spawning a subprocess. Reduces the on-disk IOC surface by one file. See
kdmapper's `main.cpp` for the load flow — most of it is command-line
parsing that we can strip.
