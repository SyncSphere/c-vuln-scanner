
```markdown
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
```

---

## 📦 Installation

Clone the repo and build:
```bash
git clone https://github.com/your-username/c-vuln-scanner.git
cd c-vuln-scanner
go build -o scanner main.go
```

---

## 🧪 Usage

### Basic Scan:
```bash
./scanner -dir /path/to/c/project
```

### Scan and Export to CSV:
```bash
./scanner -dir ./mycode --csv report.csv
```

### Scan and Export to JSON:
```bash
./scanner -dir ./mycode --json report.json
```

---

## ⚙️ CLI Flags

| Flag       | Description                                |
|------------|--------------------------------------------|
| `-dir`     | Path to the directory you want to scan     |
| `--csv`    | Output results to a CSV file               |
| `--json`   | Output results to a JSON file              |

> 🔥 Note: Scanning is recursive – all `.c` and `.cpp` files will be scanned.

---

## 📂 Sample Output

### Terminal Output:
```
[!] main.c: Potential buffer overflow: 'gets()' is unsafe (Line 12)
[!] main.c: Unused variable 'temp'
[!] Static Analysis main.c: warning: use of uninitialized variable 'x' [clang-analyzer-core.Uninitialized]
```

### JSON Output:
```json
[
  {
    "file": "main.c",
    "line_number": 12,
    "description": "Potential buffer overflow: 'gets()' is unsafe"
  },
  {
    "file": "main.c",
    "line_number": 0,
    "description": "Unused variable: 'temp'"
  }
]
```

---

## 🧠 Roadmap

- [ ] Improve variable scope detection
- [ ] Detect unused function arguments
- [ ] Add HTML report generation
- [ ] Parallel scanning for performance boost

---

## 🤝 Contributing

Pull requests and issues are welcome! Let’s build a stronger static analyzer together.

---

## 📜 License

MIT License

---

## 👨‍💻 Author

Built with ❤️ by [Your Name](https://github.com/your-username)
```

---

Would you like a badge-style version with GitHub Actions or installation via Homebrew next?
