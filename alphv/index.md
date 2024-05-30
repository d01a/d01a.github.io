# ALPHV ransomware


## Introduction

ALPHV/Blackcat is a ransomware family that uses Ransomware-as-a-service (RaaS) business model. The ransomware is written in Rust Programming language. It is highly configurable using embedded configurations or provided as command line arguments. The malware family has Windows, Linux and ESXi versions. The malware uses AES or ChaCha20 to encrypt the files and delete the volume shadow copies to decrease the possibility of any data survival. It also kills predefined set of services and Processes related to Anti-malware products, Virtualization software and other business-related and backup software.  The following graph represents the attack flow of the ransomware. 

![Untitled](img/Untitled.png)

## Analysis

### Identifying the sample.

The sample was identified by `Detect It Easy` to be compiled with `mingw` , this should be some native application. But when I looked at the strings, I knew that it was `Rust` compiled malware. 

Opening the sample in IDA will take some time to do the analysis. Rust binaries are not easy to reverse, especially with stripped -release- binaries. It is statically linked so it is expected to have so many functions and most of them are library and crate functions. Another issue is the strings (all the type system actually), the strings are stored in a structure containing a pointer to the string, length, and capacity. 

```c
struct String {
DWORD length;
DWORD buff;
DWORD capacity;
};
```

The string itself is not null-terminated string so the strings will be mixed. one way to identify the right string is to change the target region to raw data and select the start of the string to the next `Xref` , this is the termination of the string (Not working all the time).

There are a lot of strange things related to types in rust but will be explained as we move on (if I had to). Another thing to keep in mind is that there will be a lot of function calls related to error checking and memory safety related to Rust so, I will try to avoid wasting too much time to recognize them. 

Now we could start, First The main function should be found. The main function will not be clear as in native binaries for example. The `start` or `main` function identified by IDA has a lot of unrelated functions to do the initializations and the checks that Rust compiler did (like CRT initializations). The main function is passed to another function, called `lang_start` . 

![Untitled](img/Untitled%201.png)

Originally, the function’s addresses are `user_main: 0x0047B1F0` and `lang_start: 0x0049BD80`. `lang_start` just call the user main function stored in `ecx` . `user_main` also just transfers the execution to `sub_48F3C0`.

Before going into the assembly to see what this does, I looked at strings for a while and got some interesting findings.

- `/rustc/532d2b14c05f9bc20b2d27cbb5f4550d28343a36\library\core\src\` that string contains the commit hash for the rust version. The rust version used is `rustc 1.59.0`. it was out in 2021 (nighty version) this could give us a hint about the period of the malware operation.
- Configuration of the ransomware.

![Untitled](img/Untitled%202.png)

The important thing is the `extension: kh1ftzx` field. A quick google search reveals the ransomware family is `ALPHV/BlackCat` Ransomware. 

### Ransomware running options.

Trying to run the sample.

![Untitled](img/Untitled%203.png)

It has a sub-command `--access-token` which does nothing. Running the sample with any random token will work. 

![Untitled](img/Untitled%204.png)

### Command Line and Configuration Parsing

Back to `user_main` , the function calls `sub_47DF80` which calls `sub_5DFA10`. `sub_5DFA10` is used to get the Command line used, using `GetCommandLineW`. 

![Untitled](img/Untitled%205.png)

Then it parses the command line string. it extracts the subcommand passed, `--access-token` was tested and seems like it did nothing with it. Out of this function, back to the previous one `sub_47DF80`, it continues to parse the Command line checking for `-h` or `--help` presence to print the help menu. The help menu is displayed by using the console of the currently running process so in case of using a debugger, `AttachConsole` argument `dwProcessId` should be edited to another console process (CMD). 

It then loads the hardcoded configurations (Config extractor code at the end of the report) as follows: 

```json
{
  "config_id": "",
  "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq8kj5LQJngPsY7AhTaJsUXc5FrSGeKS5gw5PIqk2QPM9TY6+us8TRRzWZ7rGk1zns2klpzpRMUzLIqB8lpCkJjqkOUGfgqs+HN4VIOpoJgFY897xstJCxTc+8pYQEsSqClxJllscU0okkLSQqndIR2Gznlg3qfcwyncJAFBInyqM+L4kbwCQZ6x5HNiLe2lJn8RP2aDiMI+RS1uLYron2G7rxDTUQnxThMtgLAeko8ulaB3TpB0g4lmHCenkEZeBNs81986+MjHnv7KkiscZ7ZrezKjNaIxRs8BAcD9y+Q9QQxCvZMS01ITNXcgiItbA4dsGq1fPJ42yBkkiIodsEQIDAQAB",
  "extension": "kh1ftzx",
  "note_file_name": "RECOVER-${EXTENSION}-FILES.txt",
  "note_full_text": ">> What happened?\n\nImportant files on your network was ENCRYPTED and now they have \"${EXTENSION}\" extension.\nIn order to recover your files you need to follow instructions below.\n\n>> Sensitive Data\n\nSensitive data on your system was DOWNLOADED.\nIf you DON'T WANT your sensitive data to be PUBLISHED you have to act quickly.\n\nData includes:\n- Employees personal data, CVs, DL, SSN.\n- Complete network map including credentials for local and remote services.\n- Private financial information including: clients data, bills, budgets, annual reports, bank statements.\n- Manufacturing documents including: datagrams, schemas, drawings in solidworks format\n- And more...\n\n>> CAUTION\n\nDO NOT MODIFY ENCRYPTED FILES YOURSELF.\nDO NOT USE THIRD PARTY SOFTWARE TO RESTORE YOUR DATA.\nYOU MAY DAMAGE YOUR FILES, IT WILL RESULT IN PERMANENT DATA LOSS.\n\n>> What should I do next?\n\nFollow these simple steps to get everything back to normal:\n1) Download and install Tor Browser from: https://torproject.org/\n2) Navigate to: http://rfosusl6qdm4zhoqbqnjxaloprld2qz35u77h4aap46rhwkouejsooqd.onion/?access-key=${ACCESS_KEY}",
  "note_short_text": "Important files on your network was DOWNLOADED and ENCRYPTED.\nSee \"${NOTE_FILE_NAME}\" file to get further instructions.",
  "default_file_mode": "Auto",
  "default_file_cipher": "Best",
  "credentials": [],
  "kill_services": [
    "mepocs",
    "memtas",
    "veeam",
    "svc$",
    "backup",
    "sql",
    "vss",
    "msexchange",
    "sql$",
    "mysql",
    "mysql$",
    "sophos",
    "MSExchange",
    "MSExchange$",
    "WSBExchange",
    "PDVFSService",
    "BackupExecVSSProvider",
    "BackupExecAgentAccelerator",
    "BackupExecAgentBrowser",
    "BackupExecDiveciMediaService",
    "BackupExecJobEngine",
    "BackupExecManagementService",
    "BackupExecRPCService",
    "GxBlr",
    "GxVss",
    "GxClMgrS",
    "GxCVD",
    "GxCIMgr",
    "GXMMM",
    "GxVssHWProv",
    "GxFWD",
    "SAPService",
    "SAP",
    "SAP$",
    "SAPD$",
    "SAPHostControl",
    "SAPHostExec",
    "QBCFMonitorService",
    "QBDBMgrN",
    "QBIDPService",
    "AcronisAgent",
    "VeeamNFSSvc",
    "VeeamDeploymentService",
    "VeeamTransportSvc",
    "MVArmor",
    "MVarmor64",
    "VSNAPVSS",
    "AcrSch2Svc"
  ],
  "kill_processes": [
    "agntsvc",
    "dbeng50",
    "dbsnmp",
    "encsvc",
    "excel",
    "firefox",
    "infopath",
    "isqlplussvc",
    "msaccess",
    "mspub",
    "mydesktopqos",
    "mydesktopservice",
    "notepad",
    "ocautoupds",
    "ocomm",
    "ocssd",
    "onenote",
    "oracle",
    "outlook",
    "powerpnt",
    "sqbcoreservice",
    "sql",
    "steam",
    "synctime",
    "tbirdconfig",
    "thebat",
    "thunderbird",
    "visio",
    "winword",
    "wordpad",
    "xfssvccon",
    "*sql*",
    "bedbh",
    "vxmon",
    "benetns",
    "bengien",
    "pvlsvr",
    "beserver",
    "raw_agent_svc",
    "vsnapvss",
    "CagService",
    "QBIDPService",
    "QBDBMgrN",
    "QBCFMonitorService",
    "SAP",
    "TeamViewer_Service",
    "TeamViewer",
    "tv_w32",
    "tv_x64",
    "CVMountd",
    "cvd",
    "cvfwd",
    "CVODS",
    "saphostexec",
    "saposcol",
    "sapstartsrv",
    "avagent",
    "avscc",
    "DellSystemDetect",
    "EnterpriseClient",
    "VeeamNFSSvc",
    "VeeamTransportSvc",
    "VeeamDeploymentSvc"
  ],
  "exclude_directory_names": [
    "system volume information",
    "intel",
    "$windows.~ws",
    "application data",
    "$recycle.bin",
    "mozilla",
    "$windows.~bt",
    "public",
    "msocache",
    "windows",
    "default",
    "all users",
    "tor browser",
    "programdata",
    "boot",
    "config.msi",
    "google",
    "perflogs",
    "appdata",
    "windows.old"
  ],
  "exclude_file_names": [
    "desktop.ini",
    "autorun.inf",
    "ntldr",
    "bootsect.bak",
    "thumbs.db",
    "boot.ini",
    "ntuser.dat",
    "iconcache.db",
    "bootfont.bin",
    "ntuser.ini",
    "ntuser.dat.log"
  ],
  "exclude_file_extensions": [
    "themepack",
    "nls",
    "diagpkg",
    "msi",
    "lnk",
    "exe",
    "cab",
    "scr",
    "bat",
    "drv",
    "rtp",
    "msp",
    "prf",
    "msc",
    "ico",
    "key",
    "ocx",
    "diagcab",
    "diagcfg",
    "pdb",
    "wpx",
    "hlp",
    "icns",
    "rom",
    "dll",
    "msstyles",
    "mod",
    "ps1",
    "ics",
    "hta",
    "bin",
    "cmd",
    "ani",
    "386",
    "lock",
    "cur",
    "idx",
    "sys",
    "com",
    "deskthemepack",
    "shs",
    "ldf",
    "theme",
    "mpa",
    "nomedia",
    "spl",
    "cpl",
    "adv",
    "icl",
    "msu"
  ],
  "exclude_file_path_wildcard": [],
  "enable_network_discovery": true,
  "enable_self_propagation": true,
  "enable_set_wallpaper": true,
  "enable_esxi_vm_kill": true,
  "enable_esxi_vm_snapshot_kill": true,
  "strict_include_paths": [],
  "esxi_vm_kill_exclude": []
}
```

 The malware uses open-source library to parse the command line arguments, it is `clap` crate. 

![Untitled](img/Untitled%206.png)

After long time of debugging, the function `sub_47DF80` is used to get the command line arguments and extract the configuration passed. And extract the default configurations that hardcoded in the binary. 

### Debugging issues

The sample broke and didn’t continue in debugger even if the command line edited, but it works in usual CMD. So, to use the debugger we need something to delay execution to attach the debugger in early code. I patched the code and added a call to sleep function followed by INT 3 to instruction (Not shown in screenshot) to make it crash and put a breakpoint in any following instruction and NOP INT3 to continue :). 

![Untitled](img/Untitled%207.png)

### Preparing the environment

The malware retrieves `MachineGuid` from the registry sub-key `SOFTWARE\\Microsoft\\Cryptography` by opening the sub-key and then retrieves the value `MachineGuid` using `RegQueryValueExW` 

![Untitled](img/Untitled%208.png)

There is no such key in my machine, so it fails to read but anyway it continues. 

The next step is to execute WMIC command `wmic csproduct get UUID` But first it should open CMD. It searches for `cmd.exe` in the current working directory. 

![Untitled](img/Untitled%209.png)

If not found in the current directory, it searches for it in `system32`

![Untitled](img/Untitled%2010.png)

After finding the target executable, the following command is executed.  The `UUID` will be used later to generate access key value to be used to access the malware website on the darknet. 

```
"C:\Windows\system32\cmd.exe" /c "wmic csproduct get UUID"
```

The malware then Get a handle to a virtual file `\\?\nul` , I’m not sure but this could be used to redirect any messages to no place. 

![Untitled](img/Untitled%2011.png)

Then, the malware creates a named pipe `\\\\.\\pipe\\rust_anonymous_pipe1.<PID>.<RandomValue>`  to be used in communication in standard OUT (-11)/ERR (-12).  

![Untitled](img/Untitled%2012.png)

The pipe open mode is `PIPE_ACCESS_INBOUND|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE` The pipe has access to read, write, and connect operations. and reject remote clients **(PIPE_REJECT_REMOTE_CLIENTS).**  All the handles to the created named pipes.

![Untitled](img/Untitled%2013.png)

Finally, it is called `CreateProcessW` to create CMD process. The created process will be hidden as the flags passed are `CREATE_NO_WINDOW|CREATE_PROTECTED_PROCESS`.  

![Untitled](img/Untitled%2014.png)

To receive the return value, `WaitForMultipleObjects` is used to wait for a previously created events (2 events) then, it reads the output from the previously created pipe.

![Untitled](img/Untitled%2015.png)

### Gather victim info.

The malware creates some other thread to execute another code section (function at address 0x005EFAA0). 

![Untitled](img/Untitled%2016.png)

It calls `GetSystemInfo` to obtain some information about the victim. (_SYSTEM_INFO struct in the memory dump).

![Untitled](img/Untitled%2017.png)

It Also Call `ntdll.ZwQueryInformationProcess` with `ProcessInformationClass=0x0` to get the PEB structure of the currently running process. 

![Untitled](img/Untitled%2018.png)

It then calls `ReadProcessMemory` again to read `LDR` Structure. Also, it gets uses the same function to get the full path to the currently running executable. 

### Privilege Escalation (UAC Bypass)

The malware uses [COM moniker](https://learn.microsoft.com/en-gb/windows/win32/com/the-com-elevation-moniker) to bypass UAC and elevate its privileges. 

First it calls `CoInitializeEx` to initialize the COM library.

![Untitled](img/Untitled%2019.png)

it then uses CLSID = `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` which is CMSTPLUA is a COM interface prone to UAC bypass; To call another function that calls `CoGetObject` .

![Untitled](img/Untitled%2020.png)

it makes the string `Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` to elevate the privileges and bypass UAC. 

![Untitled](img/Untitled%2021.png)

After that, it uninitialized the COM object by calling `CoUninitialize` ****

According to [sophos' lockbit 3 blog](https://news.sophos.com/en-us/2020/04/24/lockbit-ransomware-borrows-tricks-to-keep-up-with-revil-and-maze/) this should left a trace in the registry Key `Software\Microsoft\Windows NT\CurrentVersion\ICM\Calibration` 

the following value.

`C:\WINDOWS\SysWOW64\DllHost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` 

But I couldn’t find it on my machine. 

### More preparation: elevated Child process to continue

The malware spawns another elevated process that continues execution. After that, it adds a registry key using `reg add` command. And use the previously mentioned way of executing CMD. The registry key is used to edit the `MaxMpxCt` member to increase the maximum number of outstanding client requests. 

![Untitled](img/Untitled%2022.png)

the following command is executed. 

```
 "C:\Windows\system32\cmd.exe" /c "reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v MaxMpxCt /d 65535 /t REG_DWORD /f
```

In the same (previous) screenshot we see a usage of `fsutil` utility in windows that can deal with the windows file system. The commands executed are :

```
fsutil behavior set SymlinkEvaluation R2R:1
fsutil behavior set SymlinkEvaluation R2L:1
```

These commands will be executed to set symbolic links to enable:

- Remote to Remote Symbolic links
- Remote to Local symbolic links

Another command is executed to get the entries of the ARP table.

![Untitled](img/Untitled%2023.png)

Then, it tries to reset IIS service by using `iisreset.exe /stop` .

### Delete Shadow Copies

To make sure that all the data are deleted/Encrypted, The malware then deletes all the shadow copies using `vssadmin` utility. The following are the arguments to `CreateProcessW`  

![Untitled](img/Untitled%2024.png)

The command executed is:

```
"C:\Windows\system32\cmd.exe" /c "vssadmin.exe Delete Shadows /all /quiet"
```

Then, it uses `wmic` utility to delete the shadow copies again. 

![Untitled](img/Untitled%2025.png)

The command executed is:

```
"C:\Windows\system32\cmd.exe" /c "wmic.exe Shadowcopy Delete"
```

Next, it modifies the Bootloader default to disable recovery mode using `bcdedit` utility. It runs two instances of the command line. The first was not complete so it returns an error message. The second is the following. And it runs successfully: 

![Untitled](img/Untitled%2026.png)

The command executed is:

```
"C:\Windows\system32\cmd.exe" /c "bcdedit /set {default} recoveryenabled No"
```

### Delete Event logs.

Then, it runs the following script:

```powershell
"C:\Windows\system32\cmd.exe" /c "cmd.exe /c  for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\""
```

This script is used to clear the Event logs entries. It gets all the event logs using `wevtutil.exe el` and uses `wevtutil.exe cl` to clear them. 

### Kill Targeted Services & Processes

Then it is called Global\SvcctrlStartEvent_A3752DX and `OpenScManagerW` ****according to google, this is used to duplicate windows services.  Then it uses `EnumServicesStatusExW` to list all the services and then kills the services specified in the `kill_services` in the configurations.  For every service, it runs a loop to compare against every entry in the saved `kill_services` . The targeted services to kill are:

```c
   "mepocs",
    "memtas",
    "veeam",
    "svc$",
    "backup",
    "sql",
    "vss",
    "msexchange",
    "sql$",
    "mysql",
    "mysql$",
    "sophos",
    "MSExchange",
    "MSExchange$",
    "WSBExchange",
    "PDVFSService",
    "BackupExecVSSProvider",
    "BackupExecAgentAccelerator",
    "BackupExecAgentBrowser",
    "BackupExecDiveciMediaService",
    "BackupExecJobEngine",
    "BackupExecManagementService",
    "BackupExecRPCService",
    "GxBlr",
    "GxVss",
    "GxClMgrS",
    "GxCVD",
    "GxCIMgr",
    "GXMMM",
    "GxVssHWProv",
    "GxFWD",
    "SAPService",
    "SAP",
    "SAP$",
    "SAPD$",
    "SAPHostControl",
    "SAPHostExec",
    "QBCFMonitorService",
    "QBDBMgrN",
    "QBIDPService",
    "AcronisAgent",
    "VeeamNFSSvc",
    "VeeamDeploymentService",
    "VeeamTransportSvc",
    "MVArmor",
    "MVarmor64",
    "VSNAPVSS",
    "AcrSch2Svc"
```

Same as `kill_services` , it searches for any running process that included in `kill_processes` . It gets a list of the currently running processes using `CreateToolhelp32Snapshot` and iterate through the snapshot using `Process32FirstW` and `Process32NextW` 

![Untitled](img/Untitled%2027.png)

The targeted Processes are:

```c
	 "agntsvc",
    "dbeng50",
    "dbsnmp",
    "encsvc",
    "excel",
    "firefox",
    "infopath",
    "isqlplussvc",
    "msaccess",
    "mspub",
    "mydesktopqos",
    "mydesktopservice",
    "notepad",
    "ocautoupds",
    "ocomm",
    "ocssd",
    "onenote",
    "oracle",
    "outlook",
    "powerpnt",
    "sqbcoreservice",
    "sql",
    "steam",
    "synctime",
    "tbirdconfig",
    "thebat",
    "thunderbird",
    "visio",
    "winword",
    "wordpad",
    "xfssvccon",
    "*sql*",
    "bedbh",
    "vxmon",
    "benetns",
    "bengien",
    "pvlsvr",
    "beserver",
    "raw_agent_svc",
    "vsnapvss",
    "CagService",
    "QBIDPService",
    "QBDBMgrN",
    "QBCFMonitorService",
    "SAP",
    "TeamViewer_Service",
    "TeamViewer",
    "tv_w32",
    "tv_x64",
    "CVMountd",
    "cvd",
    "cvfwd",
    "CVODS",
    "saphostexec",
    "saposcol",
    "sapstartsrv",
    "avagent",
    "avscc",
    "DellSystemDetect",
    "EnterpriseClient",
    "VeeamNFSSvc",
    "VeeamTransportSvc",
    "VeeamDeploymentSvc"
```

The malware lists all the available servers using `NetServerEnum` to display all the servers on the verbose screen. It Also retrieves the computer name using `GetComputerNameW` , it will be used in the verbose output. 

![Untitled](img/Untitled%2028.png)

The next thing it did was to prepare the ransom note file and the image. It dropped on the desktop first before any encryption. Then, while encrypting the files, it will be dropped in every directory.

![Untitled](img/Untitled%2029.png)

### Encryption Mechanism

The malware then looks for a specific locations like previous search queries in `C:\Users\<USER>\Searches\Everywhere.search-ms`  and drops the malware note there too (before encrypting). 

it makes three files in the search directory:

- The ransom note.
- `checkpoints-Everywhere.search-ms.kh1ftzx` that contain a number.
- `Everywhere.search-ms.kh1ftzx` that will be encrypted.

The malware then prepares a configuration data that describes the file being encrypted and it includes encryption mode, the encryption algorithm (chacha20 and AES) and the private key ….

```json
{"version":0,"mode":"Full","cipher":"Aes","private_key":[86,60,83,123,105,227,184,242,209,255,43,42,116,235,123,117],"data_size":248,"chunk_size":25362816,"finished":false}
```

The Encryption algorithm used is AES. The previous one was for `Everywhere.search-ms.kh1ftzx`. and the key is randomly generated. The JSON data are used to represent the file and its generated key.

The encryption process starts with adjusting the file pointer to the beginning of the file using `SetFilePointerEx` 

![Untitled](img/Untitled%2030.png)

Then, it uses `WriteFile` to over-write the content. The writing is by appending data (4-bytes then a bigger chunk then the first 4-bytes again) to the end of the file and repeat the process

![Untitled](img/Untitled%2031.png)

This picture shows the original data (First 0xF8 bytes) delimited by 4-bytes followed by RSA encrypted data (0x100) that contain the JSON data -with AES key- and 4-bytes (00 00 01 00) that was copied before the encrypted text followed by the same 4-bytes delimiter. the first bytes would be then encrypted using AES and the random generated key. 

The malware then get a handle to multiple files and read the first 4-bytes of the data. It goes through all the folder under `C:\users\<user>` and repeat the process. This is done first to the USER directory. Then it uses some Win32 API `GetLogicalDrives` to get all the available disk drives. 

![Untitled](img/Untitled%2032.png)

Then, it goes through all the drives using `FindFirstVolumeW` **and** `FindNextVolumeW` . The malware has a list of all the Drive letters. here is a small snippet. 

![Untitled](img/Untitled%2033.png)

for the found drive, it then uses `GetVolumePathNameW` to get the path to the mount point of the drive. If there is no path to it, it mount it to the system to encrypt it.

![Untitled](img/Untitled%2034.png)

And for every directory, it uses `FindFirstFileW` and `FindNextFileW` to get all the files. 

The encryption process described for `Everywhere.search-ms` is applied for all files. It first create a file with the original file name and `checkpoint` added to the beginning and the ransomware extension. Then, it generates an AES key to be used to encrypt the file and add it to the JSON data. The JSON data is then encrypted using RSA public key provided in the sample data. The RSA encrypted data are delimited by 4-bytes value = 19 47 B3 01. The original file data is then encrypted using AES cipher and the encrypted data is written back. 

There are some exclusion paths and file extensions that will not be encrypted. these exclusions are defined in the configurations of the Ransomware. 

Example of encrypted file containing the mentioned elements:

![Untitled](img/Untitled%2035.png)

The last thing is to drop on the desktop background:

![RECOVER-kh1ftzx-FILES.txt.png](img/RECOVER-kh1ftzx-FILES.txt.png)

## Config Extractor

```python
import json
import argparse
import yara

rule = '''
rule alphv_blackcat_config_extractor{
    strings:
        $a1 = {7b 22 63 6f 6e 66 69 67 5f 69 64 22} // {"config_id"
    condition:
        $a1
}
'''

end_rule = '''
rule end_delimiter{
    strings:
        $a1 = {7D 20 20 20 20 20} // }\x20\x20\x20\x20\x20
    condition:
        $a1
}
'''

def get_config(file, start,end):
    config = ''
    try:
        with open(file, 'rb') as f:
            data = f.read()
        config = data[start:end+1].decode('utf-8')
        return config
    except Exception as e:
        print('Error: {}'.format(e))
        exit(1)

def print_config(config):
    try:
        config_json = json.loads(config)
        config_json = json.dumps(config_json, indent=4)
        print('Config:')
        print('-'*40)
        print(config_json)
    except Exception as e:
        print('Invalid JSON. Error: {}'.format(e))
        print('Config:')
        print('-'*20)
        print(config)

def main():
    parser = argparse.ArgumentParser(description='ALPHV/Blackcat ransomware config extractor')
    parser.add_argument('-f', '--file', help='Path to the PE file', required=True)
    args = parser.parse_args()
    try: 
        compiled_rule = yara.compile(source=rule)
        matches = compiled_rule.match(args.file)
        start = matches[0].strings[0][0]
        compiled_end = yara.compile(source=end_rule)
        matches_end = compiled_end.match(args.file)

        for end_match in matches_end[0].strings:
            # print(start)
            # print(end_match[0])
            if end_match[0] > start:
                # print(end_match[0])
                config = get_config(args.file,start, end_match[0])
                print_config(config)
                return
    except Exception as e:
        print("No matches found")
        print('Error: {}'.format(e))
        exit(1)

if __name__ == '__main__':
    main()
```

Usage:

![Untitled](img/Untitled%2036.png)

## YARA

```python
rule ALPHV_BlackCat_Ransomware {
    meta:
        malware = "ALPHV/BlackCat Ransomware"
        hash = "ecea6b772742758a2240898ef772ca11aa9d870aec711cffab8994c23044117c"
        author = "d01a"
        description = "detect ALPHV/BlackCat Ransomware"

    strings:
        $alphv1 = "No Access Token Provided" ascii
        $alphv2 = "locker::core::os::windows" ascii
        $alphv3 = "locker::core::pipeline" ascii
        $alphv4 = "\\\\.\\pipe\\__rust_anonymous_pipe1__." ascii
        $alphv5 = "src/bin/encrypt_app/app.rs" ascii
        $alphv6 = "src/core/os/windows/privilege_escalation.rs" ascii
        $alphv7 = "rc/bin/encrypt_app/windows.rs" ascii
        $alphv8 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii
        $alphv9 = "bcdedit /set {default} recoveryenabled No" ascii
        $alphv10 = "vssadmin.exe Delete Shadows /all /quiet" ascii
        $alphv11 = "wmic.exe Shadowcopy Delete" ascii
        $alphv12 = "wmic csproduct get UUID" ascii

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and 7 of them
}
```

Hybrid-analysis search result [Free Automated Malware Analysis Service - powered by Falcon Sandbox - Search results from HA Community Files (hybrid-analysis.com)](https://www.hybrid-analysis.com/yara-search/results/c2410a8ac36941bc25515b194f0a4efbd79739faaf4bd8bb77c232b0ffbea905)

## IOCs

| IOC | Description |
| --- | --- |
| ecea6b772742758a2240898ef772ca11aa9d870aec711cffab8994c23044117c | ALPHV sha256 checksum |
| wmic csproduct get UUID | WMIC command  |
| vssadmin.exe Delete Shadows /all /quiet | command to delete shadow copies |
| wmic.exe Shadowcopy Delete | command to delete shadow copies |
| bcdedit /set {default} | wrong command used |
| bcdedit /set {default} recoveryenabled No | command to disable recovery |
| cmd.exe /c  for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\" | CMD loop to delete event logs |
| fsutil behavior set SymlinkEvaluation R2R:1 | change filesystem symbolic links |
| fsutil behavior set SymlinkEvaluation R2L:1 | change filesystem symbolic links |
| iisreset.exe /stop | command to reset IIS service |
| arp -a | command to get the ARP table |
| \\.\pipe\rust_anonymous_pipe1.<PID>.<RandomValue> | named piped schema used |
| \\?\nul | virtual file used |
| {3E5FC7F9-9A51-4367-9063-A120244FBEC7} | CLSID used to bypass UAC  |
| reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v MaxMpxCt /d 65535 /t REG_DWORD /f | command to edit lanman server speed |
| SOFTWARE\Microsoft\Cryptography\MachineGuid | quired registry key |
| checkpoints-<Original_Filename>.kh1ftzx | ransomware-created file |
| RECOVER-kh1ftzx-FILES.txt.png | ransom note wallpaper |
| RECOVER-kh1ftzx-FILES.txt | the ransom notes |
| src/bin/encrypt_app/app.rs | malware source code file name |
| src/core/os/windows/privilege_escalation.rs | malware source code file name |
| src/core/os/windows/samba.rs | malware source code file name |
| src/core/os/windows/system_info.rs | malware source code file name |
| rc/bin/encrypt_app/windows.rs | malware source code file name |

## MITRE ATT&CK

| Execution |  |
| --- | --- |
| https://attack.mitre.org/techniques/T1059/003 | Command and Scripting Interpreter: Windows Command Shell |
| https://attack.mitre.org/techniques/T1047/ | Windows Management Instrumentation |
| Privilege Escalation |  |
| https://attack.mitre.org/techniques/T1548/002/ | Abuse Elevation Control Mechanism: Bypass User Account Control |
| https://attack.mitre.org/techniques/T1055/ | Process Injection |
| Defense Evasion |  |
| https://attack.mitre.org/techniques/T1548/002/ | Abuse Elevation Control Mechanism: Bypass User Account Control |
| https://attack.mitre.org/techniques/T1222/001/ | File and Directory Permissions Modification: Windows File and Directory Permissions Modification |
| https://attack.mitre.org/techniques/T1112/ | Modify Registry |
| https://attack.mitre.org/techniques/T1562/001/ | Impair Defenses: Disable or Modify Tools |
| https://attack.mitre.org/techniques/T1070/001/ | Indicator Removal: Clear Windows Event Logs |
| https://attack.mitre.org/techniques/T1070/004/ | Indicator Removal: File Deletion |
| Discovery |  |
| https://attack.mitre.org/techniques/T1083 | File and Directory Discovery |
| https://attack.mitre.org/techniques/T1135/ | Network Share Discovery |
| https://attack.mitre.org/techniques/T1069/002/ | Permission Groups Discovery: Domain Groups |
| https://attack.mitre.org/techniques/T1057/ | Process Discovery |
| https://attack.mitre.org/techniques/T1018/ | Remote System Discovery |
| https://attack.mitre.org/techniques/T1033/ | System Owner/User Discovery |
| https://attack.mitre.org/techniques/T1007/ | System Service Discovery |
| Impact |  |
| https://attack.mitre.org/techniques/T1485/ | Data Destruction |
| https://attack.mitre.org/techniques/T1486/ | Data Encrypted for Impact |
| https://attack.mitre.org/techniques/T1490/ | Inhibit System Recovery |
| https://attack.mitre.org/techniques/T1489/ | Service Stop |
|  |  |

![ALPHV_Ransomware.png](img/ALPHV_Ransomware.png)

## References

[https://research.checkpoint.com/2023/rust-binary-analysis-feature-by-feature/](https://research.checkpoint.com/2023/rust-binary-analysis-feature-by-feature/)

[https://www.youtube.com/watch?v=q8irLfXwaFM](https://www.youtube.com/watch?v=q8irLfXwaFM)

[https://ss64.com/nt/fsutil.html](https://ss64.com/nt/fsutil.html)

[https://securityscorecard.com/research/deep-dive-into-alphv-blackcat-ransomware/](https://securityscorecard.com/research/deep-dive-into-alphv-blackcat-ransomware/)

[https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/](https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/)

[https://news.sophos.com/en-us/2020/04/24/lockbit-ransomware-borrows-tricks-to-keep-up-with-revil-and-maze/](https://news.sophos.com/en-us/2020/04/24/lockbit-ransomware-borrows-tricks-to-keep-up-with-revil-and-maze/)

[Microsoft Windows - COM Session Moniker Privilege Escalation (MS17-012) - Windows local Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/41607)

[The many lives of BlackCat ransomware | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/)
