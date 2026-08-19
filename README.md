# CrystalPotato

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/crystalpotato/Screenshot_1.png)

Crystal port of [GodPotato](https://github.com/BeichenDream/GodPotato): local privilege escalation from accounts with `SeImpersonatePrivilege` (IIS/MSSQL service accounts, Network Service, Local Service, etc.) to SYSTEM. It works on Windows (8–11 / Server 2012–2022) by abusing the DCOM OXID Resolver and named pipe impersonation.


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
| `-p NAME` | Custom pipe name (default: `GodPotato`) |
| `-h` | Show help |

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/crystalpotato/Screenshot_1.png)