# TmComm

TmComm (Trend Micro Common Client Module) - kernel mode driver used by Trend Micro endpoint security products (Apex One, OfficeScan, RootkitBuster, Worry-Free Business Security).

My opensource driver does not use the original source codes and is a reverse-engineered driver using [Ghidra](https://en.wikipedia.org/wiki/Ghidra) and [Radare2](https://en.wikipedia.org/wiki/Radare2). The rights have not been violated, and the new driver cannot be signed due to the EV certificate. I hope that the vulnerabilities can be closed using my security patches.

The main goal of the project is to recreate a secure driver with fixed vulnerabilities and errors made by past developers.

### Functions

Driver TmComm.sys provides low-level system inspection and inter-process communication:

- Process scanning, inspection, and handle management
- Low-level kernel filesystem operations and file disposition
- System structure hook detection (SSDT, object type headers, routines)
- Direct physical disk inspection via XrayApi
- Core communication and unload notification dispatching

Fixed vulnerabilities in opensource driver TmComm.sys:

- [x] (CVE-2020-24557)[https://nvd.nist.gov/vuln/detail/CVE-2020-24557]
  - Insufficient Access Control: Device object opened with world-accessible DACL (fixed using `IoCreateDeviceSecure` with SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)`)
  - Arbitrary Process Handle Elevation: IOCTL 0x90004027 (fixed by blocking elevated write/injection access masks and system PIDs)
- [x] (CVE-2019-18187)[https://nvd.nist.gov/vuln/detail/CVE-2019-18187]
  - Arbitrary File Deletion / Manipulation: IOCTL 0x9000402B (fixed with file path validation and blocking critical system path deletion)
- [x] (CVE-2020-24556)[https://nvd.nist.gov/vuln/detail/CVE-2020-24556]
  - Arbitrary File Deletion via Symlink/Traversal: IOCTL 0x9000402B (fixed with directory traversal protection)

Fixed no publish vulnerabilities and bugs which contributors to this project found:

- Arbitrary kernel code execution via user-mode callback in `IoControlRegisterUnloadNotify` ([view code](trueapi.c))
- Arbitrary process termination in `IoControlTerminateProcess` ([view code](process.c))
- Missing device deletion on symbolic link creation failure ([view code](main.c))

Authors:

- 2026 - Herman Semenoff <<GermanAizek@yandex.ru>> ([germanaizek.github.io](https://germanaizek.github.io))
- Trend Micro Inc. <<security@trendmicro.com>>
