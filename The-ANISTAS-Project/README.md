# The-ANISTAS-Project: Automated NIST Auditing System
A Go-based tool for automating the compliance process for NIST SP 800-171 on nonfederal information systems.

## Table of Contents
* About
* Features
* Tech Stack
* Getting Started
* Usage
* Project Status & Roadmap
* License

## About
ANISTAS (Automated NIST Auditing System) simplifies the auditing process for SP 800-171, making compliance easy. The tool automates auditing NIST controls, compares systems for compliance, and provides actionable reports and dashboards.

## Features
* Core audit engine, auditing up to 10+ NIST SP 800-171 controls.
* CLI interface for audits and results.
* Pass/fail displayed per control
* (Tentative) Dashboard UI - Compliance scorecards, history, trend analysis.
* (Tentative) Full automation for system scanning.

## Tech Stack
**Language:** Go 1.20+
**CLI Framework:** spf13 Cobra
**Database:** SQLite
**Other Libraries:** 
* Viper
* Fyne
**NIST Control(s) Framework:** OSCAL
**Compliance Engine:** Custom Go modules parsing OSCAL-formatted regulatory documents

# Getting Started
## *CLI Cloning*
```
# Clone repo
$ git clone https://github.com/UUCompSci/The-ANISTAS-Project.git 
$ cd anistas # Build
$ go build -o anistas ./cmd/audit-cli 
# Run a sample audit 
$ ./anistas audit --config testdata/sample_system.yaml
```
## Licence
MIT License

## Author
Eston Yandell
