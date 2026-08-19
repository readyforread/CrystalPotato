# CrystalPotato

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/crystalpotato/Screenshot_1.png)

Crystal port of [GodPotato](https://github.com/BeichenDream/GodPotato): local privilege escalation from accounts with `SeImpersonatePrivilege` (IIS/MSSQL service accounts, Network Service, Local Service, etc.) to SYSTEM. It works on Windows (8–11 / Server 2012–2022) by abusing the DCOM OXID Resolver and named pipe impersonation.

Strings that reveal the tool's behavior (`combase.dll`, pipe paths, SIDs, SDDL, protocol names, IP addresses) are XOR-obfuscated at compile time using a Crystal macro — they don't appear in a `strings` dump of the binary. By default only command output is printed; use `-d` for verbose exploit diagnostics.


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
| `-d` | Verbose debug output |
| `-h` | Show help |

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/crystalpotato/Screenshot_1.png)
