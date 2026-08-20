# CrystalPotato

Crystal port of [GodPotato](https://github.com/BeichenDream/GodPotato): local privilege escalation from accounts with `SeImpersonatePrivilege` (IIS/MSSQL service accounts, Network Service, Local Service, etc.) to SYSTEM. It works on Windows (8–11 / Server 2012–2022) by abusing the DCOM OXID Resolver and named pipe impersonation.

Sensitive Windows APIs are resolved dynamically via PEB walking and invoked through indirect syscall stubs, keeping them out of the binary's Import Address Table. All strings are XOR-obfuscated at compile time. By default only the command output is printed.

<p align="center">
  <img src="https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/CrystalPotato/Screenshot_1.png" alt="CrystalPotato" width="420">
</p>


## Build

```
crystal build CrystalPotato.cr -o CrystalPotato.exe --release
```


## Usage

```
CrystalPotato.exe -c <COMMAND>
```

| Flag | Description |
|---|---|
| `-c CMD` | Command to execute as SYSTEM (required) |
| `-p NAME` | Custom pipe name (default: `Crystal`) |
| `-d` | Debug output (repeat for full trace: `-d -d`) |
| `-h` | Show help |

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/CrystalPotato/Screenshot_2.png)
