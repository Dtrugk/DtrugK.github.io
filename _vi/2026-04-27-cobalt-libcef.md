---
title: "Vibe Reversing một loader Cobalt Strike 3 stages"
date: 2026-04-27 10:00:00 +0700
categories: [Phân tích Malware, Cobalt Strike]
tags: [reverse-engineering, cobalt-strike, dll-sideloading, reflective-loader, ida-pro, mcp, ai-assisted-re]
translation_key: cobalt-libcef
media_subpath: /assets/img/posts/cobalt-libcef
description: >-
  Một ae trong team gắn cờ một libcef.dll không ký, được tải
  bởi NVIDIA Notification trong một cuộc hunt. Với IDA Pro MCP điều phối
  phân tích tĩnh, tôi đã vibe reverse và dump thành công 3 stage và lấy được IOC
---

## TL;DR

> Giải nén một loader Cobalt Strike 3 tầng được sideload vào **NVIDIA
> Notification** thông qua một `libcef.dll` không được ký — toàn bộ
> chuỗi tấn công, IOC, và config beacon trong một buổi chiều. **IDA Pro
> MCP** điều khiển toàn bộ phân tích tĩnh; những gì lẽ ra phải mất một
> tuần grunt work năm ngoái giờ trở thành một cuộc trò chuyện liên tục
> với decompiler.
{: .prompt-info }

Một tuần trước, một thành viên trong team threat hunting của tôi gắn
cờ một **`libcef.dll` không được ký** được tải bởi tiến trình hợp pháp
**NVIDIA Notification**.[^1] Đây là dấu hiệu kinh điển của DLL
sideloading — `libcef.dll` là runtime của Chromium Embedded Framework,
thường được NVIDIA ký số và phát hành. *"Đây là phần mềm hợp pháp, hay
tôi đang gặp incident?"*

![Tổng quan chuỗi loader](binary_overview.png)

Payload gồm 3 stage: một libcef.dll không ký, một reflective loader, và
một beacon Cobalt Strike. Libcef.dll extract reflective loader được dấu ở cuối file DLL khác. 
Reflective loader, RC4 với key là drive serial của host, byte magic
PE bị swap thành lệnh x64 hợp lệ, một lớp XOR phủ lên import table của
implant, và một beacon Cobalt Strike với malleable C2 profile được
tinh chỉnh giả dạng traffic Amazon analytics. Giải nén toàn bộ
và parse được config beacon bằng `1768.py`.
## Stage 0 — Surface Triage

Trước khi đụng vào IDA, lướt qua PEStudio xem có gì đáng chú ý hay không, kết quả cho thấy
5 cái khá là sus

- **129 stub + 1 export thật.** Các RVA của export tăng đều với stride
  `0x10` byte (`0x2B30, 0x2B40, 0x2B50, …`) — trừ ordinal 102,
  `cef_string_utf8_to_utf16`, nhảy đến `.text:0x000039F0`, hoàn toàn
  ngoài mảng stub. Ordinal 103 và 104 lấp vào slot mà 102 bỏ trống,
  vậy nên binary có chính xác một export thật ẩn giữa 129 export ngụy
  trang.
- **Hai TLS callback** trong directory table. TLS callback chạy lúc
  map, trước `DllMain` và trước khi bất kỳ export nào được gọi. Kết
  hợp với phát hiện về export, kiến trúc hiện ra rõ ràng: định danh
  CEF giả để qua mặt static check, TLS callback cho thực thi thật.
- **Chênh lệch kích thước 70×.** Mẫu: **909 KB**. `libcef.dll` chính
  thức của NVIDIA: **65.33 MB**. Không có vũ trụ nào mà 909 KB chứa
  được runtime Chromium Embedded Framework.
- **Original filename: `LIBRARY.dll`.** Một chuỗi boilerplate còn sót
  trong PE version resource
- **SHA-256 chưa từng thấy trên VirusTotal.** Sample mới, không phải
  recompile của một build đã biết.

![PEStudio export view: 129 stub stride đều 0x10, ordinal 102 nhảy đến 0x39F0](export_func.png)

> Định danh ngụy trang (CEF export giả + cert tái sử dụng) + thực thi
> lúc load (TLS callback). Stage 1 bắt đầu ở `.text:0x000039F0` — và
> đó là nơi tôi mở IDA.
{: .prompt-tip }

## Stage 1 — libcef Analysis

> **Nhắc lại: một DLL sideload có thể thực thi ở đâu?**
> Ba entry point kích hoạt khi host gọi `LoadLibrary` — TLS callback
> (lúc map, trước `DllMain`), bản thân `DllMain`, và bất kỳ export nào
> mà host gọi. Phải kiểm tra cả ba; loader thật thường đẩy việc lên
> upstream (TLS) hoặc xuống downstream (một export hot duy nhất) để
> giữ `DllMain` nhàm chán.

Stage 0 đã gắn cờ cả ba: hai TLS callback (địa chỉ chưa biết cho đến
khi mở IDA), một entry point `DllMain` chuẩn, và ordinal 102
(`cef_string_utf8_to_utf16`) — export thật duy nhất trong table, và là
thứ mà bất kỳ host CEF nào cũng gọi trong init.

**TLS callback và `DllMain` đều sạch** — MSVC C-runtime scaffolding
(walker `_dyn_tls_dtor` do compiler sinh, boilerplate
`_DllMainCRTStartup`, `DllMain` của user trống), không có đường nào từ
hai cái này dẫn đến code độc hại. Phát hiện "hai TLS callback" của
Stage 0 là false positive — quan sát đúng, suy luận sai. **Luồng đáng
ngờ là export.**

### Ord 102 — the actual trigger

`cef_string_utf8_to_utf16` (RVA `0x39F0`) là export thật duy nhất mà
host gọi trong CEF init. Shim hai dòng:

```c
__int64 cef_string_utf8_to_utf16() {
    MalwareMain();
    return 101;
}
```

Cross-reference xác nhận: `MalwareMain` được tiếp cận bởi **chính xác
một** code caller trong toàn bộ binary — chính shim này. Không có
đường TLS, không có đường `DllMain`, không có export nào khác.

![Pseudocode điểm vào MalwareMain](psuedo.png)

> Giả thuyết của Stage 0 đúng một nửa, sai một nửa. Ord 102 là
> trigger; TLS là red herring. `MalwareMain` là toàn bộ đóng góp của
> tác giả malware vào binary này — mọi function khác trong `libcef.dll`
> đều hoặc là CEF stub giả hoặc là MSVC scaffolding.
{: .prompt-tip }

## Inside `MalwareMain` — the Stage-1 pipeline

13 bước, tất cả đều có chủ đích. ~30 dòng source. Nhóm thành năm phase.

![Pseudocode điểm vào MalwareMain](decompiled.png)

### Phase 1 — API resolution (kernel32 first)

![InitAPIHashConstants](1777291484851.png)

Một static ctor C++ (`InitApiHashConstants_ctor`, được gọi từ
`RunGlobalCtors`) ghi các hằng số hash API vào `.data` lúc runtime.
PE trên đĩa có toàn số 0 ở đó — strings/constants scan không tìm thấy gì.

Thuật toán hash, lấy trực tiếp từ resolver:

![Pseudocode hàm hash](1777291656948.png)

```c
hash = 18462;                                    // seed = 0x481E
for each byte c in name:
    hash = (9 * hash + c) & 0xFFFFFFFF;
```

Hai biến thể: hash module-name lowercase trước (qua `CharLowerA`),
hash export-name giữ nguyên case.
[HashDB](https://hashdb.openanalysis.net/) tự động phân giải toàn bộ
table chỉ với một click.

`ResolveApis_1` đi qua `PEB.Ldr.InMemoryOrderModuleList`, hash từng
`BaseDllName`, tìm `0x201551D6` (= `kernel32.dll`), rồi phân giải 17
API vào `qword_1D5CF3030..0x30B0`.

![Phân giải API address từ kernel32](1777291761206.png)

**Bộ công cụ trước-unhook**: `GetWindowsDirectoryA`, `CreateFileA`,
`CreateFileMappingA`, `MapViewOfFile`, `VirtualProtect`, `CloseHandle`.
Kernel32 trước — EDR hook ntdll mạnh hơn, nên việc unhook tự lọt qua.

### Phase 2 — NTDLL unhook

`MappingNTDLLImage` mở `C:\Windows\System32\NTDLL.DLL` và map nó như
một image section:

```c
hMap  = CreateFileMappingA(hFile, NULL,
                           SEC_IMAGE_NO_EXECUTE | PAGE_READONLY,  // 0x11000002
                           0, 0, NULL);
base  = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
```

`SEC_IMAGE_NO_EXECUTE` (`0x11000000`) bảo kernel layout file như một PE
image — relocation được áp dụng, section ở VirtualAddress, view
non-executable. Tôi có một bản ntdll sạch khớp byte-by-byte với những
gì OS loader đã tạo cho ntdll đang sống.

`OverWriteCurrentNTDLL` đi qua `PEB.Ldr` đến module được load thứ hai
(luôn là ntdll), tìm `.text`, và copy bản sạch lên bản đã hooked dưới
quyền `PAGE_EXECUTE_WRITECOPY` (yên tĩnh hơn RWX; copy-on-write giữ
modification process-private):

```c
VirtualProtect(text, size, PAGE_EXECUTE_WRITECOPY, &oldProt);  // 0x80
memcpy(text, fresh_text, size);
VirtualProtect(text, size, oldProt, &oldProt);
```

> **Mọi userland EDR hook trong `ntdll` đã biến mất trong tiến trình
> này.** Từ đây trở đi, bất kỳ direct-syscall stub nào malware gọi
> đều chạy unhooked.
{: .prompt-info }

`ResolveApis_2` sau đó chạy cùng hash function với module hash
`0x9485AF86` (= `ntdll.dll`), populate 8 API ntdll — bộ công cụ
module-stomping:

| API | Vai trò |
|---|---|
| `LdrLoadDll` | Load (hoặc lookup) stomp target |
| `ZwAllocateVirtualMemory` | Allocate page trong target |
| `NtProtectVirtualMemory` | Toggle quyền page của target (RX → RW → RX) |
| `NtFlushInstructionCache` | Bắt buộc sau khi ghi exec code |
| `NtCreateThreadEx` | Spawn payload bị stomp như một thread |
| `NtWaitForSingleObject` | Wait trên thread đã spawn |
| `NtCreateFile` | Mở file qua direct-syscall |
| `NtDelayExecution` | Backend của `CustomSleep` |

Hai lựa chọn tố cáo thiết kế: `NtCreateThreadEx` (không phải
`CreateThread` từ k32) và `NtFlushInstructionCache` (không có
equivalent ở k32).

### Phase 3 — Anti-analysis

Ba check liên tục:

- **`CustomSleep(1000)` — sandbox check.** Tự đo bằng `GetTickCount64`
  trước và sau `NtDelayExecution`; nếu delta đo được ngắn hơn sleep
  được yêu cầu, `ExitProcess(11)`. Bắt được sandbox no-op `Sleep` để
  fast-track phân tích.
- **`CheckDebug`** — `PEB->BeingDebugged == 1 → ExitProcess(1)`.
- **`CheckDebuggerViaNtQuery`** — `GlobalMemoryStatusEx`; nếu
  `ullTotalPhys` trông quá nhỏ cho một host thật, `ExitProcess(11)`.
  Heuristic không thường gặp; phần lớn loader dùng `ProcessDebugPort`
  hoặc `ProcessDebugObjectHandle`.

### Phase 4 — Locate and decrypt the payload

Cần ba thứ: stomp target, RC4 key, và payload path.

- **Stomp target.** `GetModuleFileNameA(qword_1D5CF30F8, buf, 260)`
  ghi path của module ở handle `qword_1D5CF30F8` (set lúc init). Cặp
  `(HMODULE, path)` được cache trong `LookupOrPebwalkStompTarget` cho
  handoff ở Phase 5.
- **RC4 key.** `DriveSerialCollector` đọc volume serial của ổ C: qua
  `GetVolumeInformationW` và format thành `XXXX-XXXX` (ví dụ
  `7872-B362`). Cùng cách derive key như `decryptor.py`. Host-bound:
  chuyển encrypted blob đi máy khác, volume serial đổi, key đổi,
  giải mã ra rác.
- **Payload path.** Được build từ năm local literal mixed-width trên
  stack (tổng 34 byte), giải mã in-place:

  ```c
  for (int i = 0; i < 34; i++)
      p[i] ^= (i + 103);
  // → "C:\Windows\Help\AppVReporting.dll"
  ```

  Không có chuỗi nào trong `.rdata`. Không có XOR key buffer. Bulk-XOR
  scanner sẽ bỏ sót nó.

File được mở qua `nt_NtCreateFile` (đường unhook), rồi đọc bằng
kernel32 (`GetFileSize` + `VirtualAlloc` + `ReadFile` + `CloseHandle`).
Cả ntdll và k32 file API đều unhook ở thời điểm này — EDR mù.

`Important_ProcessPayload` parse PE của carrier, chọn section theo
index (chọn theo PE32/PE32+ + WOW64), scan tìm `FE ED FA CE`, lấy
các byte 8 byte sau marker, và RC4-decrypt in-place.

![FE ED FA CE](1777292758167.png)

`0xFEEDFACE` là Mach-O fat-binary magic. File scanner cố parse nó như
Mach-O sẽ bail.

### Phase 5 — Hand off to module stomping

`CustomSleep(3000)` lần thứ hai, copy byte đã giải mã vào vector có
size phù hợp, rồi:

```c
StompSetupScanFileQueueAAndRun(&decrypted_buffer);
```

Stage 1 hoàn tất. Stomp primitive: chọn một section trong stomp target
đã cache, `VirtualProtect` writable, `memcpy` shellcode vào, restore
protection, jump in. Stage 2 chạy bên trong vùng địa chỉ của một
module hợp pháp đã được ký — với bất kỳ EDR thread-creation hook nào
còn sót sau unhook, thread trông như đang thực thi bên trong một DLL
đã được biết là tốt.

> Khi `MalwareMain` return: một stage-2 buffer đã giải mã trong memory,
> và đường thực thi đang hoạt động qua module stomping. ~30 dòng
> source. 99% còn lại của `libcef.dll` là CEF stub giả + MSVC
> scaffolding.
{: .prompt-tip }

## Stage 2 — AppVReporting.dll (the carrier)

> **Nội dung của stage này.** Encrypted blob bên trong
> `AppVReporting.dll` RC4-decrypt thành ~256 KB sRDI shellcode — một
> Stephen Fewer ReflectiveLoader đóng gói cùng PE payload tầng kế.
> Tôi extract blob, decrypt nó, rồi đi qua 12 bước của loader trong
> IDA. Hai thủ thuật chống-static analysis kiếm được callout riêng:
> magic-byte swap đóng vai trò như một CPU instruction, và nơi XOR
> key cho các import bị obfuscate được giấu.
{: .prompt-info }

![HxD view của AppVReporting.dll cho thấy marker FEEDFACE](1777293226003.png)

`AppVReporting.dll` nằm ở `C:\Windows\Help\` — vị trí lạ, tên file
hợp lý. Mở trong HxD: một PE thật ở đầu, rồi `FE ED FA CE` ở giữa,
rồi ~256 KB rác entropy cao.

Hai thứ cần lấy: encrypted blob (`bytes[marker + 8 :]`), và volume
serial của ổ C: trên host gốc (`7872-B362` ở đây — RC4 key). Claude
gộp extract + decrypt thành một script duy nhất — cùng RC4 với
`Important_ProcessPayload`, cùng định dạng key với `DriveSerialCollector`:

<details markdown="1">
<summary>🐍 Script extract + decrypt đầy đủ (click để mở rộng)</summary>

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

Chạy nó và tôi nhận được `payload_decrypted.bin` — ~256 KB stage-1
shellcode. Sanity check báo `--> Not a PE` và đó là đúng: byte
`0x00..0x47` là alignment sled, byte `0x48` là `AY` (swapped `MZ`),
và `0x48+0xEC` là `FM` (swapped `PE`). PE header thật còn nguyên dưới
swap.

Load file vào IDA dạng raw binary 64-bit. Một segment, RWX, `0x3FE48`
byte. Auto-analysis của IDA tìm thấy 37 function — nhưng không có
entry point, không export, không symbol. Tìm dispatcher trong shellcode
thô tốn nhiều công hơn so với một PE bình thường. View tôi dựa vào
cho việc này là **Function call graph** của IDA
(`View → Open subviews → Function calls`) — nó vẽ hàm nào gọi hàm
nào, nên dispatcher trên cùng và các helper ở leaf hiện ra trong nháy
mắt:

![IDA Function call graph view của shellcode](1777294025102.png)

Cấu trúc lộ ra: sRDI ReflectiveLoader ở trên, các helper ở leaf phía
dưới, và một PE payload nhúng đóng gói ngay sau code của loader.

### Entry point at byte `0x48` — the AY = `pop r9` trick

Ba lệnh và một call:

```asm
0x48:  pop  r9                    ; "AY" disassemble ở đây
0x4a:  push r9
0x4c:  push rbp
0x4d:  mov  rbp, rsp
0x50:  sub  rsp, 20h
0x57:  lea  rbx, [self]
0x61:  add  rbx, 15F88h           ; offset đến ReflectiveLoader
0x68:  call rbx
```

> **Cặp byte hai-công-việc.** `41 59` là `AY` đối với một PE-magic
> scanner — sai byte, bail. Đối với CPU, `41 59` là `pop r9`. Shellcode
> CALL vào `0x48`; CALL push một return address; `pop r9` lấy nó ra;
> `push r9` khôi phục stack. r9 giờ chứa địa chỉ của chính loader —
> tự định vị trong hai byte cũng kiêm luôn vai trò ngụy trang định danh.
{: .prompt-tip }

### `ReflectiveLoader` — 12-step sRDI mapper

Ở RVA `0x15FD0`, 633 byte, 11 callee. Flow Stephen Fewer chuẩn với hai
twist đáng chú ý:

1. **Patch-check.** Loader bắt đầu bằng
   `strcpy("AAAAAAAABBBBBBBB", scratch)`. Nếu injector ghi đè những
   byte đó lúc runtime, `init_from_patched_config()` decode beacon
   configuration đã được patch. Mặc định khi đứng yên, bị patch khi
   đang bay.
2. **`find_self_base_by_mz_scan()`** — đi ngược từ return address của
   loader tìm `AY` + `FM` (magic đã swap), không phải `MZ` + `PE`.
   Đây là lý do thủ thuật `pop r9` cần thiết.
3. `resolve_apis_by_hash()`, `copy_pe_headers()`,
   `copy_sections_to_image()`, `resolve_imports()` + `decode_name_xor()`,
   `apply_base_relocations()`, `finalize_memory_protections()` — tất
   cả đều là các bước reflective-loader chuẩn.
4. **Hai PE flag được tái mục đích:**
   - `Characteristics & 0x8000` chọn alloc granularity (64 vs 4 byte).
   - `Characteristics & 0x1000` (`IMAGE_FILE_SYSTEM`, không bao giờ
     set trên user-mode DLL) chuyển entry sang `NT+128` thay vì
     `AddressOfEntryPoint`.
5. **DllMain 5-arg.** Call cuối là
   `entry(self_base, a2, 1=DLL_PROCESS_ATTACH, mapped_base, a4)` — ba
   tham số dư mang beacon config và tasking context. Convention beacon
   Cobalt Strike.

> **`decode_name_xor` lấy key từ `IMAGE_FILE_HEADER.NumberOfSymbols`.**
> XOR đơn byte là tầm thường; điểm khôn ngoan là *nơi* key sống.
> `NumberOfSymbols` đã chết trong các PE hiện đại từ thời COFF —
> không PE validator nào để ý, không string scanner nào tìm thấy key.
{: .prompt-tip }

Loader map toàn bộ shellcode như một PE lớn (dùng AY/FM header mà nó
vừa tự định vị) và jump tới entry point — entry này nằm bên trong một
DLL payload nhúng đóng gói sau code loader (~`0x17000` trở đi). Đi qua
12 bước end-to-end với file sẽ tạo ra một PE sạch; đó chính xác là
những gì `emulator_stage1.py` làm, dump ra `stage2_mapped.bin` cho
tầng kế.

## Stage 3 — Cobalt Strike 4.2 beacon

> **Nội dung của stage này.** Sau khi emulate đúng logic của stage 2
> shellcode loader, tôi đã extract thành công `stage3_implant.bin`
> dưới dạng một file PE sạch, và nó là một DLL beacon Cobalt Strike
> 4.2 vanilla. Không còn loader, không còn lớp obfuscation. Công việc
> ở đây là parse beacon configuration nhúng bằng
> [`1768.py`](https://blog.didierstevens.com/programs/cobalt-strike-tools/)
> của Didier Stevens và đọc xem operator chọn gì. Tiêu đề: license
> ID là **`0x12345678`** — watermark CS bị leak/crack, không phải ID
> customer duy nhất.
{: .prompt-info }

Triage qua `strings` cho `stage3_implant.bin` lộ ra `beacon x64` —
signature kinh điển của Cobalt Strike beacon. Xác nhận danh tính trước
khi parse config.

<details markdown="1">
<summary>📋 Output đầy đủ của <code>1768.py</code> (click để mở rộng)</summary>

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
0x0033 process-inject-execute           0x0003 0x0080 '\x06\x00\x02\x00\x00\x00\x06ntdll\x00\x00\x00\x00\rkernel32.dll\x00\x00\x00\x00\tAddAtomW\x00\x04'
0x0034 process-inject-allocation-method 0x0001 0x0002 1
0x0000
Guessing Cobalt Strike version: 4.2 (max 0x003a)
Sanity check Cobalt Strike config: OK
Sleep mask 64-bit 4.2 deobfuscation routine found: 0x00010a49 (LSFIF: b't3E;')
Public key config entry found: 0x0003c05c (xorKey 0x2e) (LSFIF: b'././.,.&.,./.,/')
Public key header found: 0x0003c062 (xorKey 0x2e) (LSFIF: b'././.,.&.,./.,/')
```

</details>

Highlights từ config được parse:

| Field | Value | Notes |
|---|---|---|
| Payload type | `windows-beacon_https-reverse_https` | HTTPS C2, hướng reverse |
| Port | `443` | Ẩn trong noise của TLS |
| Sleep / Jitter | 69,843 ms (~70 s) / 27 % | Callback chậm, cadence ngẫu nhiên |
| C2 server | `www.tata.com,/broadcast` | GET URI là `/broadcast` |
| POST URI | `/1/events/com.amazon.csm.csa.prod` | Bắt chước Amazon CSA video analytics |
| Host header | `Host: cdn.typeform.com\r\n` | Không khớp với `www.tata.com` thực — dấu hiệu domain-fronting |
| User-Agent | `Mozilla/5.0 (Windows NT 11.0; WOW64; ...) Chrome/111` | `WOW64` trên UA Win11 — hơi sai |
| Spawn-to | `%windir%\sysnative\gpupdate.exe` (x64) | Living-off-the-land binary |
| Process inject | RWX → RX, min alloc `0x413C` | CS injection chuẩn |
| Watermark (license ID) | `305419896` = **`0x12345678`** | CS bị leak/crack |

> **License ID `0x12345678` là watermark Cobalt-Strike bị leak.**
> License CS hợp pháp sinh ra giá trị duy nhất. ID `0x12345678` đã
> được quan sát trên hàng nghìn mẫu không liên quan trong nhiều năm —
> nó là watermark bạn nhận được từ các CS builder bị crack/leak trôi
> nổi trong underground. **Không phải attribution — operator profile.**
> Cho biết actor dùng CS bị crack, không phải actor là ai.
{: .prompt-tip }

### The malleable C2 profile

HTTP traffic ngụy trang thành Amazon CSA (Customer Service Analytics)
video-interaction telemetry. Lệnh `Build Output` của beacon prepend
một JSON envelope được tinh chỉnh thủ công; byte beacon được encode
đi vào field `video.id` dưới dạng `BASE64 URL`:

```json
{"events":[{"data":{"schemaId":"csa.VideoInteractions.1",
  "application":"Retail:Prod:","requestId":"MBFV82TTQV2JNBKJJ50B",
  "title":"Amazon.com. Spend less. Smile more.",
  "subPageType":"desktop","session":{"id":"133-9905055-2677266"},
  "video":{"id":"<beacon data base64url here>","playerMode":"INLINE",
           "videoRequestId":"MBFV82TTQV2JNBKJJ50B","isAudioOn":"false",
           "player":"IVS","event":"NONE"}}}]}
```

Outbound traffic trông không khác gì một tab nói chuyện với amazon.com
nếu bạn chỉ kiểm tra hình dạng JSON. **Nhưng `session.id` và
`requestId` là tĩnh** — copy-paste từ một phiên thật, không
regenerate mỗi call. Hai host bị nhiễm beacon qua profile này sẽ phát
ra `session.id` và `requestId` giống hệt nhau, điều mà một analytics
pipeline thật sẽ không bao giờ tạo ra. Sự bất đối xứng đó là một
detection lever sạch.

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

[^1]: Mọi chi tiết nhận dạng về host, môi trường, và thời gian đã được
    thay đổi hoặc tổng quát hóa. Các chi tiết kỹ thuật giữ nguyên.


## Final thoughts
AI giờ mạnh quá, sắp thành AI Orchestrator rồi.....