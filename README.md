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

- [ ] (CVE-2020-24557)[https://nvd.nist.gov/vuln/detail/CVE-2020-24557]
- [ ] (CVE-2019-18187)[https://nvd.nist.gov/vuln/detail/CVE-2019-18187]
- [ ] (CVE-2020-24556)[https://nvd.nist.gov/vuln/detail/CVE-2020-24556]

Authors:

- 2026 - Herman Semenoff <<GermanAizek@yandex.ru>> ([germanaizek.github.io](https://germanaizek.github.io))
- Trend Micro Inc. <<security@trendmicro.com>>
