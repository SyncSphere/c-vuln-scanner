# 🔍 C/C++ Vulnerability Scanner

A simple static analysis tool built with Go to scan C and C++ files for known vulnerabilities, unsafe function usage, and unused variables. Supports export of results to CSV and JSON formats and integrates with `clang-tidy` for deeper static analysis.

---

## 🚀 Features

- ✅ Detects common C/C++ security issues:
  - Buffer overflows (`gets`, `strcpy`, `sprintf`, `strcat`)
  - Concurrency hazards (`fork`, `pthread_create`)
  - Weak cryptographic functions (`MD5`, `DES`)
  - Chroot jail misconfigurations
- ✅ Detects **unused variables**
- ✅ Performs **static analysis** using `clang-tidy`
- ✅ Exports results to **CSV** and **JSON**
- ✅ Supports scanning entire directories recursively
- ✅ Easy CLI interface

---

## 🛠️ Requirements

- [Go (1.17+)](https://golang.org/dl/)
- [clang-tidy](https://clang.llvm.org/extra/clang-tidy/) (for static analysis)

Install on Debian-based systems:
```bash
sudo apt install clang-tidy
