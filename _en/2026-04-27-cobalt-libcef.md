---
title: "Vibe Reversing a 3-stage Cobalt Strike loader"
date: 2026-04-27 10:00:00 +0700
categories: [Malware Analysis, Cobalt Strike]
tags: [reverse-engineering, cobalt-strike, dll-sideloading, reflective-loader, ida-pro, mcp, ai-assisted-re]
translation_key: cobalt-libcef
media_subpath: /assets/img/posts/cobalt-libcef
description: >-
  A teammate flagged an unsigned libcef.dll loaded by NVIDIA Notification
  during a hunt. With IDA Pro MCP driving the static analysis, I
  vibe-reversed all 3 stages and pulled the IOCs.
# image:
#   path: /assets/img/posts/cobalt-libcef-cover.png
#   alt: "Cobalt Strike loader chain — four stages from libcef.dll to beacon"
---

## TL;DR

> Unpacking a 3-stage Cobalt Strike loader sideloaded into **NVIDIA
> Notification** via an unsigned `libcef.dll` — full chain, IOCs, and
> beacon config in a single afternoon. **IDA Pro MCP** drove the static
> analysis end to end; what would have been a week of grunt work last
> year became one continuous conversation with the decompiler.
{: .prompt-info }

A teammate on my threat hunting team flagged an **unsigned `libcef.dll`**
loaded by the legitimate **NVIDIA Notification** process last week.[^1]
Textbook DLL sideloading red flag — `libcef.dll` is the Chromium Embedded
Framework runtime, normally shipped signed by NVIDIA. *"Is this legit,
or do I have an incident?"*

![Loader chain overview](binary_overview.png)

Payload is three stages: an unsigned `libcef.dll`, a reflective loader,
and a Cobalt Strike beacon. `libcef.dll` extracts the reflective loader
hidden at the tail of a second DLL on disk. From there: RC4 keyed to the
host's drive serial, PE magic bytes swapped for valid x64 instructions,
an XOR layer over the implant's import table, and a beacon with a
hand-tuned malleable C2 profile dressed up as Amazon analytics traffic.
Fully unpacked and the beacon config parsed by `1768.py`.

## Stage 0 — Surface Triage

Before touching IDA, a quick PEStudio pass to see if anything's noteworthy.
Five findings — all sus:

- **129 stubs + 1 real export.** The export RVAs march in a perfectly uniform
  `0x10`-byte stride (`0x2B30, 0x2B40, 0x2B50, …`) — except for ordinal 102,
  `cef_string_utf8_to_utf16`, which jumps to `.text:0x000039F0`, far outside
  the stub array. Ordinals 103 and 104 fill the slot 102 vacated, so the
  binary has exactly one real export hidden among 129 cosmetic ones.
- **Two TLS callbacks** in the directory table. TLS callbacks fire at map time,
  before `DllMain` and before any export is called. Combined with the export
  finding, the architecture is obvious: fake-CEF identity for static checks,
  TLS callbacks for actual execution.
- **70× size delta.** Sample: **909 KB**. Legitimate NVIDIA-shipped
  `libcef.dll`: **65.33 MB**. There is no universe where 909 KB contains the
  Chromium Embedded Framework runtime.
- **Original filename: `LIBRARY.dll`.** A boilerplate string left in the
  PE version resource.
- **SHA-256 unseen on VirusTotal.** Fresh sample, not a recompile of a
  known build.

![PEStudio export view: 129 stubs at uniform 0x10 stride, ordinal 102 jumps to 0x39F0](export_func.png)

> Identity cover (fake CEF exports + reused cert) + load-time execution
> (TLS callbacks). Stage 1 starts at `.text:0x000039F0` — and that's where
> I open IDA.
{: .prompt-tip }

## Stage 1 — libcef Analysis

> **Refresher: where can a sideloaded DLL actually execute?**
> Three entry points fire when the host calls `LoadLibrary` — TLS callbacks
> (at map time, before `DllMain`), `DllMain` itself, and any export the host
> calls. Check all three; loaders often move work upstream (TLS) or
> downstream (one hot export) to keep `DllMain` boring.

Stage 0 already flagged all three: two TLS callbacks (addresses unknown
until IDA), a standard `DllMain` entry, and ordinal 102
(`cef_string_utf8_to_utf16`) — the only real export in the table, and
something any CEF host calls during init.

**TLS callbacks and `DllMain` both check out as clean** — MSVC C-runtime
scaffolding (compiler-emitted `_dyn_tls_dtor` walker, `_DllMainCRTStartup`
boilerplate, empty user `DllMain`), no path from either to anything
malicious. Stage 0's "two TLS callbacks" finding was a false positive —
observation right, inference wrong. **The suspicious thread is the export.**

### Ord 102 — the actual trigger

`cef_string_utf8_to_utf16` (RVA `0x39F0`) is the single real export the
host calls during CEF init. Two-line shim:

```c
__int64 cef_string_utf8_to_utf16() {
    MalwareMain();
    return 101;
}
```

Cross-references confirm it: `MalwareMain` is reached by **exactly one**
code caller in the entire binary — this shim. No TLS path, no `DllMain`
path, no other export.

![Pseudocode of MalwareMain entry point](psuedo.png)

> Stage 0's hypothesis was right on one count, wrong on the other. Ord 102
> is the trigger; TLS is a red herring. `MalwareMain` is the entire malware
> author's contribution to this binary — every other function in
> `libcef.dll` is either a fake CEF stub or MSVC scaffolding.
{: .prompt-tip }

## Inside `MalwareMain` — the Stage-1 pipeline

13 steps, all deliberate. ~30 lines of source. Grouped into five phases.

![Pseudocode of MalwareMain entry point](decompiled.png)

### Phase 1 — API resolution (kernel32 first)

![InitAPIHashConstants](1777291484851.png)

A C++ static ctor (`InitApiHashConstants_ctor`, fired from `RunGlobalCtors`)
writes the API hash constants into `.data` at runtime. The on-disk PE has
zeros there — strings/constants scans find nothing.

Hash algorithm, lifted from the resolver:

![Hashing function pseudo code](1777291656948.png)

```c
hash = 18462;                                    // seed = 0x481E
for each byte c in name:
    hash = (9 * hash + c) & 0xFFFFFFFF;
```

Two variants: module-name hash lowercases first (via `CharLowerA`),
export-name hash is case-preserving.
[HashDB](https://hashdb.openanalysis.net/) auto-resolves the whole table
in one click.

`ResolveApis_1` walks `PEB.Ldr.InMemoryOrderModuleList`, hashes each
`BaseDllName`, finds `0x201551D6` (= `kernel32.dll`), then resolves 17 APIs
into `qword_1D5CF3030..0x30B0`.

![Resolve API Address from kernel32](1777291761206.png)

The **before-unhook toolkit**: `GetWindowsDirectoryA`, `CreateFileA`,
`CreateFileMappingA`, `MapViewOfFile`, `VirtualProtect`, `CloseHandle`.
Kernel32 first — EDRs hook ntdll harder, so the unhook itself slips through.

### Phase 2 — NTDLL unhook

`MappingNTDLLImage` opens `C:\Windows\System32\NTDLL.DLL` and maps it as
an image section:

```c
hMap  = CreateFileMappingA(hFile, NULL,
                           SEC_IMAGE_NO_EXECUTE | PAGE_READONLY,  // 0x11000002
                           0, 0, NULL);
base  = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
```

`SEC_IMAGE_NO_EXECUTE` (`0x11000000`) tells the kernel to lay out the file
as a PE image — relocations applied, sections at their VirtualAddress, view
non-executable. I get a clean ntdll matching what the OS loader produced
for the live one.

`OverWriteCurrentNTDLL` walks `PEB.Ldr` to the second loaded module
(always ntdll), finds `.text`, and copies fresh over hooked under
`PAGE_EXECUTE_WRITECOPY` (quieter than RWX; copy-on-write keeps the
modification process-private):

```c
VirtualProtect(text, size, PAGE_EXECUTE_WRITECOPY, &oldProt);  // 0x80
memcpy(text, fresh_text, size);
VirtualProtect(text, size, oldProt, &oldProt);
```

> **Every userland EDR hook in `ntdll` is gone in this process.** From here
> on, any direct-syscall stub the malware calls runs unhooked.
{: .prompt-info }

`ResolveApis_2` then runs the same hash function with module hash
`0x9485AF86` (= `ntdll.dll`), populating 8 ntdll APIs — the
module-stomping toolkit:

| API | Role |
|---|---|
| `LdrLoadDll` | Load (or look up) the stomp target |
| `ZwAllocateVirtualMemory` | Allocate pages in the target |
| `NtProtectVirtualMemory` | Toggle target page perms (RX → RW → RX) |
| `NtFlushInstructionCache` | Required after writing exec code |
| `NtCreateThreadEx` | Spawn the stomped payload as a thread |
| `NtWaitForSingleObject` | Wait on the spawned thread |
| `NtCreateFile` | Direct-syscall file open |
| `NtDelayExecution` | Backs `CustomSleep` |

Two choices give the design away: `NtCreateThreadEx` (not `CreateThread`
from k32) and `NtFlushInstructionCache` (no k32 equivalent exists).

### Phase 3 — Anti-analysis

Three checks back-to-back:

- **`CustomSleep(1000)` — sandbox check.** Times itself with `GetTickCount64`
  before and after `NtDelayExecution`; if the measured delta is shorter than
  the requested sleep, `ExitProcess(11)`. Catches sandboxes that no-op
  `Sleep` to fast-track analysis.
- **`CheckDebug`** — `PEB->BeingDebugged == 1 → ExitProcess(1)`.
- **`CheckDebuggerViaNtQuery`** — `GlobalMemoryStatusEx`; if `ullTotalPhys`
  looks too small for a real host, `ExitProcess(11)`. Unusual heuristic;
  most loaders use `ProcessDebugPort` or `ProcessDebugObjectHandle`.

### Phase 4 — Locate and decrypt the payload

Three things needed: the stomp target, the RC4 key, and the payload path.

- **Stomp target.** `GetModuleFileNameA(qword_1D5CF30F8, buf, 260)` writes
  the path of the module at the handle in `qword_1D5CF30F8` (set during
  init). The `(HMODULE, path)` pair gets cached in
  `LookupOrPebwalkStompTarget` for the handoff in Phase 5.
- **RC4 key.** `DriveSerialCollector` reads the C: volume serial via
  `GetVolumeInformationW` and formats it as `XXXX-XXXX` (e.g. `7872-B362`).
  Same key derivation as `decryptor.py`. Host-bound: move the encrypted
  blob, the volume serial changes, the key changes, decryption produces
  garbage.
- **Payload path.** Built from five mixed-width local literals on the
  stack (34 bytes total), decoded in place:

  ```c
  for (int i = 0; i < 34; i++)
      p[i] ^= (i + 103);
  // → "C:\Windows\Help\AppVReporting.dll"
  ```

  No string in `.rdata`. No XOR key buffer. Bulk-XOR scanners miss it.

The file is opened via `nt_NtCreateFile` (unhooked path), then read with
kernel32 (`GetFileSize` + `VirtualAlloc` + `ReadFile` + `CloseHandle`).
Both ntdll and k32 file APIs are unhooked at this point — EDR is blind.

`Important_ProcessPayload` parses the carrier PE, picks a section by index
(chosen from PE32/PE32+ + WOW64), scans for `FE ED FA CE`, takes the bytes
8 past the marker, and RC4-decrypts in place.

![FE ED FA CE](1777292758167.png)

`0xFEEDFACE` is the Mach-O fat-binary magic. File scanners that try to parse
it as Mach-O bail.

### Phase 5 — Hand off to module stomping

A second `CustomSleep(3000)`, copy decrypted bytes into a sized vector,
then:

```c
StompSetupScanFileQueueAAndRun(&decrypted_buffer);
```

Stage 1 is done. The stomp primitive: pick a section in the cached stomp
target, `VirtualProtect` writable, `memcpy` the shellcode in, restore
protection, jump in. Stage 2 runs inside a legitimate, signed module's
address range — to any EDR thread-creation hook that survived the unhook,
the thread looks like execution inside a known-good DLL.

> When `MalwareMain` returns: a decrypted stage-2 buffer in memory, and an
> active execution path through module stomping. ~30 lines of source. The
> other 99% of `libcef.dll` is fake CEF stubs + MSVC scaffolding.
{: .prompt-tip }

## Stage 2 — AppVReporting.dll (the carrier)

> **What's in this stage.** The encrypted blob inside `AppVReporting.dll`
> RC4-decrypts to ~256 KB of sRDI shellcode — a Stephen Fewer ReflectiveLoader
> bundled with the next-stage payload PE. I extract the blob, decrypt it,
> then walk the loader's 12 steps in IDA. Two anti-static tricks earn their
> own callouts along the way: the magic-byte swap that doubles as a CPU
> instruction, and where the XOR key for the obfuscated imports lives.
{: .prompt-info }

![HxD view of AppVReporting.dll showing the FEEDFACE marker](1777293226003.png)

`AppVReporting.dll` sits at `C:\Windows\Help\` — odd location, plausible
filename. Open it in HxD: a real PE up front, then `FE ED FA CE` somewhere
in the middle, then ~256 KB of high-entropy junk.

Two things to grab: the encrypted blob (`bytes[marker + 8 :]`), and the C:
volume serial of the original host (`7872-B362` here — the RC4 key). Claude
folded extract + decrypt into one script — same RC4 as
`Important_ProcessPayload`, same key format as `DriveSerialCollector`:

<details markdown="1">
<summary>🐍 Full extract + decrypt script (click to expand)</summary>

```python
#!/usr/bin/env python3
"""Extract & RC4-decrypt the Stage-1 payload from AppVReporting.dll."""
import sys

DLL    = r"C:\Users\admin\Downloads\MinhDD\C__windows_help_AppVReporting.dll\AppVReporting.dll"
MARKER = b"\xFE\xED\xFA\xCE"
KEY    = b"7872-B362"                  # formatted C: volume serial
ENC    = "payload_encrypted.bin"
OUT    = "payload_decrypted.bin"


# --- RC4 (matches the malware's implementation exactly) ---
def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for k in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[k] = data[k] ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


# --- 1. Extract: scan for FEEDFACE, take everything 8 bytes past the marker ---
data = open(DLL, "rb").read()
off  = data.find(MARKER)
if off < 0:
    sys.exit("[-] FEEDFACE marker not found")

ct = data[off + 8:]                    # marker(4) + 4 reserved = payload at +8
open(ENC, "wb").write(ct)
print(f"[+] Marker @ file offset {off:#x}  payload={len(ct)}B -> {ENC}")

# --- 2. Decrypt: RC4 with the formatted volume serial as key ---
pt = rc4(ct, KEY)
open(OUT, "wb").write(pt)
print(f"[+] Decrypted {len(pt)} bytes -> {OUT}")
print(f"    First 16 bytes: {pt[:16].hex(' ')}")

# --- 3. Sanity check: did I land on a PE? ---
if pt[:2] == b"MZ":
    e_lfanew = int.from_bytes(pt[0x3C:0x40], "little")
    if e_lfanew < len(pt) - 4 and pt[e_lfanew:e_lfanew+4] == b"PE\x00\x00":
        print("    --> Looks like a PE file (MZ + PE header OK)")
    else:
        print("    --> MZ header present (PE header not validated)")
elif pt[:4] == b"\x4D\x5A\x90\x00":
    print("    --> PE file (standard MZ stub)")
else:
    print("    --> Not a PE. Might be raw shellcode or wrong key.")
```

</details>

Run it and I get `payload_decrypted.bin` — ~256 KB of stage-1 shellcode.
The sanity check fires `--> Not a PE` and that's correct: bytes `0x00..0x47`
are an alignment sled, byte `0x48` is `AY` (swapped `MZ`), and `0x48+0xEC`
is `FM` (swapped `PE`). The real PE headers are intact under the swap.

Load the file in IDA as a 64-bit raw binary. Single segment, RWX,
`0x3FE48` bytes. IDA's auto-analysis finds 37 functions — but no entry
point, no exports, no symbols. Finding the dispatcher in raw shellcode
takes more work than in a normal PE. The view I lean on for this is IDA's
**Function call graph** (`View → Open subviews → Function calls`) — it
plots which functions call which, so the topmost dispatcher and the
leaf-most helpers fall out at a glance:

![IDA Function call graph view of the shellcode](1777294025102.png)

The structure jumps out: sRDI ReflectiveLoader at the top,
helper leaves below, and an embedded payload PE bundled past the loader code.

### Entry point at byte `0x48` — the AY = `pop r9` trick

Three instructions and a call:

```asm
0x48:  pop  r9                    ; "AY" disassembles here
0x4a:  push r9
0x4c:  push rbp
0x4d:  mov  rbp, rsp
0x50:  sub  rsp, 20h
0x57:  lea  rbx, [self]
0x61:  add  rbx, 15F88h           ; offset to ReflectiveLoader
0x68:  call rbx
```

> **The two-job byte pair.** `41 59` is `AY` to a PE-magic scanner — wrong
> bytes, bail. To the CPU, `41 59` is `pop r9`. The shellcode CALLs into
> `0x48`; CALL pushes a return address; `pop r9` retrieves it; `push r9`
> restores the stack. r9 now holds the loader's own address — self-locating
> in two bytes that double as identity cover.
{: .prompt-tip }

### `ReflectiveLoader` — 12-step sRDI mapper

At RVA `0x15FD0`, 633 bytes, 11 callees. Standard Stephen Fewer flow with
two notable twists:

1. **Patch-check.** Loader starts with `strcpy("AAAAAAAABBBBBBBB", scratch)`.
   If the injector overwrote those bytes at runtime,
   `init_from_patched_config()` decodes the patched beacon configuration.
   Default at rest, patched in flight.
2. **`find_self_base_by_mz_scan()`** — walks backward from the loader's
   return address looking for `AY` + `FM` (swapped magic), not `MZ` + `PE`.
   This is what makes the `pop r9` trick necessary.
3. `resolve_apis_by_hash()`, `copy_pe_headers()`, `copy_sections_to_image()`,
   `resolve_imports()` + `decode_name_xor()`, `apply_base_relocations()`,
   `finalize_memory_protections()` — all standard reflective-loader steps.
4. **Two repurposed PE flags:**
   - `Characteristics & 0x8000` selects alloc granularity (64 vs 4 bytes).
   - `Characteristics & 0x1000` (`IMAGE_FILE_SYSTEM`, never set on user-mode
     DLLs) routes the entry to `NT+128` instead of `AddressOfEntryPoint`.
5. **5-arg DllMain.** Final call is
   `entry(self_base, a2, 1=DLL_PROCESS_ATTACH, mapped_base, a4)` — three
   extra args carry beacon config and tasking context. Cobalt Strike beacon
   convention.

> **`decode_name_xor` keys off `IMAGE_FILE_HEADER.NumberOfSymbols`.**
> Single-byte XOR is trivial; the cleverness is *where* the key lives.
> `NumberOfSymbols` has been dead in modern PEs since COFF — no PE
> validator notices, no string scanner finds the key.
{: .prompt-tip }

The loader maps the whole shellcode as one big PE (using the AY/FM headers
it just self-located) and jumps to the entry point — which lands inside an
embedded payload DLL bundled past the loader code (~`0x17000` and beyond).
Walking the 12 steps end-to-end against the file produces a clean PE;
that's exactly what `emulator_stage1.py` does, dumping `stage2_mapped.bin`
for the next stage.

## Stage 3 — Cobalt Strike 4.2 beacon

> **What's in this stage.** After emulating exact logic of stage 2 shellcode loader, i have successfully extracted `stage3_implant.bin` with a clean PE file, and it is a vanilla Cobalt Strike
> 4.2 beacon DLL. No more loaders, no more obfuscation layers. The work
> here is parsing the embedded beacon configuration with Didier Stevens's
> [`1768.py`](https://blog.didierstevens.com/programs/cobalt-strike-tools/)
> and reading what the operator chose. Headline: the license ID is
> **`0x12345678`** — the leaked / cracked CS watermark, not a unique
> customer ID.
{: .prompt-info }

A quick `strings` pass over `stage3_implant.bin` turns up `beacon x64` —
the canonical Cobalt Strike beacon signature. Identity confirmed before
parsing the config.


<details markdown="1">
<summary>📋 Full <code>1768.py</code> parsed output (click to expand)</summary>

```
python 1768.py stage3_implant.bin
File: stage3_implant.bin
payloadType: 0x00007530
payloadSize: 0x00000001
intxorkey: 0x00000001
id2: 0x000000ff
Config found: xorkey b'.' 0x0003c030 0x000870a3
0x0001 payload type                     0x0001 0x0002 8 windows-beacon_https-reverse_https
0x0002 port                             0x0001 0x0002 443
0x0003 sleeptime                        0x0002 0x0004 69843
0x0004 maxgetsize                       0x0002 0x0004 1399607
0x0005 jitter                           0x0001 0x0002 27
0x0007 publickey                        0x0003 0x0100 30819f300d06092a864886f70d010101050003818d00308189028181009e2a216672aab66f513004deb640580db4b7ed1e4d345eef0254bc6bf438bc10ec29b1aa67291d144c8512cb72175671323b38c03e6943055e10a5bcdb1c8e81ed370aa4630edb15bc12b58ff836b2b2b1065cfa13ba529bc75611ffa6396eed430ac3637b397a34070755819a6b3dc420417627f63492ab5cf7fb8c4eb7fbcf020301000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0x0008 server,get-uri                   0x0003 0x0100 'www.tata.com,/broadcast'
0x000e SpawnTo                          0x0003 0x0010 'eõ&\x0b§]H<]ÃèÐã½j«'
0x001d spawnto_x86                      0x0003 0x0040 '%windir%\\syswow64\\gpupdate.exe'
0x001e spawnto_x64                      0x0003 0x0040 '%windir%\\sysnative\\gpupdate.exe'
0x001f CryptoScheme                     0x0001 0x0002 0
0x001a get-verb                         0x0003 0x0010 'GET'
0x001b post-verb                        0x0003 0x0010 'POST'
0x001c HttpPostChunk                    0x0002 0x0004 0
0x0025 license-id                       0x0002 0x0004 305419896
0x0026 bStageCleanup                    0x0001 0x0002 1
0x0027 bCFGCaution                      0x0001 0x0002 1
0x0009 useragent                        0x0003 0x0100 'Mozilla/5.0 (Windows NT 11.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5520.225 Safari/537.36'
0x000a post-uri                         0x0003 0x0040 '/1/events/com.amazon.csm.csa.prod'
0x000b Malleable_C2_Instructions        0x0003 0x0100
  Transform Input: [7:Input,4,1:1308,1:1,2:194,3]
   Print
   Remove 1308 bytes from end
   Remove 1 bytes from end
   Remove 194 bytes from begin
   BASE64
0x000c http_get_header                  0x0003 0x0200
  Const_header Accept: application/json, text/plain, */*
  Const_header Accept-Language: en-US,en;q=0.5
  Const_header Origin: https://www.amazon.com
  Const_header Referer: https://www.amazon.com
  Const_header Sec-Fetch-Dest: empty
  Const_header Sec-Fetch-Mode: cors
  Const_header Sec-Fetch-Site: cross-site
  Const_header Te: trailers
  Build Metadata: [7:Metadata,3,6:x-amzn-RequestId]
   BASE64
   Header x-amzn-RequestId
0x000d http_post_header                 0x0003 0x0200
  Const_header Accept: */*
  Const_header Origin: https://www.amazon.com
  Build Output: [7:Output,13,2:{"events":[{"data":{"schemaId":"csa.VideoInteractions.1","application":"Retail:Prod:,"requestId":"MBFV82TTQV2JNBKJJ50B","title":"Amazon.com. Spend less. Smile more.","subPageType":"desktop","session":{"id":"133-9905055-2677266"},"video":{"id":",1:"
,1:"playerMode":"INLINE","videoRequestId":"MBFV82TTQV2JNBKJJ50B","isAudioOn":"false","player":"IVS","event":"NONE"}}}}]},4]
   BASE64 URL
   Prepend {"events":[{"data":{"schemaId":"csa.VideoInteractions.1","application":"Retail:Prod:,"requestId":"MBFV82TTQV2JNBKJJ50B","title":"Amazon.com. Spend less. Smile more.","subPageType":"desktop","session":{"id":"133-9905055-2677266"},"video":{"id":"
   Append "

   Append "playerMode":"INLINE","videoRequestId":"MBFV82TTQV2JNBKJJ50B","isAudioOn":"false","player":"IVS","event":"NONE"}}}}]}
   Print
  Build SessionId: [7:SessionId,13,6:x-amz-rid]
   BASE64 URL
   Header x-amz-rid
0x0036 HostHeader                       0x0003 0x0080 'Host: cdn.typeform.com\r\n'
0x0032 UsesCookies                      0x0001 0x0002 0
0x0020 proxy                            0x0003 0x0080 'http://10.60.117.113:8080'
0x0023 proxy_type                       0x0001 0x0002 0
0x003a TCP_FRAME_HEADER                 0x0003 0x0080 '\x00&\x05\x00\x0c\x03\x10\x00\x00\x00<\x00\x00\x00\x00\x00\x00\x00Ð\x16Ð\x16\x11I\x00\x00\x04\x00135\x00i\x00\x01'
0x0039 SMB_FRAME_HEADER                 0x0003 0x0080 '\x00\x04'
0x0037 EXIT_FUNK                        0x0001 0x0002 0
0x0028 killdate                         0x0002 0x0004 0
0x0029 textSectionEnd                   0x0002 0x0004 177872
0x002a ObfuscateSectionsInfo            0x0003 0x0030 '\x00\x10\x00\x00Ð¶\x02\x00\x00À\x02\x00r¸\x03\x00\x00À\x03\x00\x88\x85\x04\x00\x00\x90\x04\x004°\x04\x00\x00À\x04\x00^Ï\x04'
0x002b process-inject-start-rwx         0x0001 0x0002 64 PAGE_EXECUTE_READWRITE
0x002c process-inject-use-rwx           0x0001 0x0002 32 PAGE_EXECUTE_READ
0x002d process-inject-min_alloc         0x0002 0x0004 16700
0x002e process-inject-transform-x86     0x0003 0x0100 '\x00\x00\x00\t\x90\x90\x90\x90\x90\x90\x90\x90\x90'
0x002f process-inject-transform-x64     0x0003 0x0100 '\x00\x00\x00\t\x90\x90\x90\x90\x90\x90\x90\x90\x90'
0x0035 process-inject-stub              0x0003 0x0010 'µJþ\x01ìjuíó^\x1aDø½9)'
0x0033 process-inject-execute           0x0003 0x0080 '\x06\x00\x02\x00\x00\x00\x06ntdll\x00\x00\x00\x00\x0eDbgUiContinue\x00\x01\x08\x02\x07\x00\x12\x00\x00\x00\rkernel32.dll\x00\x00\x00\x00\tAddAtomW\x00\x04'
0x0034 process-inject-allocation-method 0x0001 0x0002 1
0x0000
Guessing Cobalt Strike version: 4.2 (max 0x003a)
Sanity check Cobalt Strike config: OK
Sleep mask 64-bit 4.2 deobfuscation routine found: 0x00010a49 (LSFIF: b't3E;')
Public key config entry found: 0x0003c05c (xorKey 0x2e) (LSFIF: b'././.,.&.,./.,/')
Public key header found: 0x0003c062 (xorKey 0x2e) (LSFIF: b'././.,.&.,./.,/')
```

</details>

Highlights from the parsed config:

| Field | Value | Notes |
|---|---|---|
| Payload type | `windows-beacon_https-reverse_https` | HTTPS C2, reverse direction |
| Port | `443` | Hides in TLS noise |
| Sleep / Jitter | 69,843 ms (~70 s) / 27 % | Slow callbacks, randomized cadence |
| C2 server | `www.tata.com,/broadcast` | GET URI is `/broadcast` |
| POST URI | `/1/events/com.amazon.csm.csa.prod` | Mimics Amazon CSA video analytics |
| Host header | `Host: cdn.typeform.com\r\n` | Mismatched with actual `www.tata.com` — domain-fronting tell |
| User-Agent | `Mozilla/5.0 (Windows NT 11.0; WOW64; ...) Chrome/111` | `WOW64` on a Win11 UA — slightly off |
| Spawn-to | `%windir%\sysnative\gpupdate.exe` (x64) | Living-off-the-land binary |
| Process inject | RWX → RX, min alloc `0x413C` | Standard CS injection |
| Watermark (license ID) | `305419896` = **`0x12345678`** | Leaked / cracked CS |

> **License ID `0x12345678` is the leaked-Cobalt-Strike watermark.**
> Legitimate CS licenses generate unique values. The `0x12345678` ID has
> been observed across thousands of unrelated samples for years — it's the
> watermark you get from cracked / leaked CS builders floating around the
> underground. **Not attribution — operator profile.** Tells you the actor
> used a cracked CS, not who the actor is.
{: .prompt-tip }

### The malleable C2 profile

The HTTP traffic dresses up as Amazon CSA (Customer Service Analytics)
video-interaction telemetry. The beacon's `Build Output` instruction
prepends a hand-tuned JSON envelope; the encoded beacon bytes go into the
`video.id` field as `BASE64 URL`:

```json
{"events":[{"data":{"schemaId":"csa.VideoInteractions.1",
  "application":"Retail:Prod:","requestId":"MBFV82TTQV2JNBKJJ50B",
  "title":"Amazon.com. Spend less. Smile more.",
  "subPageType":"desktop","session":{"id":"133-9905055-2677266"},
  "video":{"id":"<beacon data base64url here>","playerMode":"INLINE",
           "videoRequestId":"MBFV82TTQV2JNBKJJ50B","isAudioOn":"false",
           "player":"IVS","event":"NONE"}}}]}
```

Outbound traffic looks indistinguishable from a tab talking to amazon.com
if you only check the JSON shape. **But the `session.id` and `requestId`
are static** — copy-pasted from a real session, not regenerated per-call.
Two infected hosts beaconing through this profile would emit identical
`session.id` and `requestId`, which a real analytics pipeline would never
produce. That asymmetry is a clean detection lever.

### IOCs

```
Sideloaded DLL (carrier 1):
  Path:    <NVIDIA Notification install dir>\libcef.dll
  Size:    909,312 bytes
  SHA-256: E15AC675F3BF141C21D912D408A9E8B4E74EFD2298705746F6EFDAD5ACA66DA7
  Cert:    Signed by NVIDIA Corporation; valid-to 2021-07-10 (expired)

Encrypted payload (carrier 2):
  Path:    C:\Windows\Help\AppVReporting.dll
  Marker:  FE ED FA CE  (followed by 4 reserved bytes + RC4 ciphertext)

Cryptography:
  RC4 key:  formatted C: volume serial, e.g. "7872-B362"
  XOR key:  0xC3, stashed in IMAGE_FILE_HEADER.NumberOfSymbols (NT+16)
  Magic:   AY/FM (swapped MZ/PE) at byte 0x48 of stage-1 shellcode

Cobalt Strike beacon (Final payload):
  Version:        4.2
  License ID:     0x12345678 (leaked/cracked watermark)
  C2 domain:      www.tata.com
  C2 GET URI:     /broadcast
  C2 POST URI:    /1/events/com.amazon.csm.csa.prod
  Host header:    cdn.typeform.com   (domain-fronting tell)
  Proxy:          http://10.60.117.113:8080
  Spawn-to (x64): %windir%\sysnative\gpupdate.exe
  Spawn-to (x86): %windir%\syswow64\gpupdate.exe
  Sleep/Jitter:   69,843 ms / 27 %
```

[^1]: All identifying details about the host, environment, and timing have
    been altered or genericized. The technical details are unchanged.

