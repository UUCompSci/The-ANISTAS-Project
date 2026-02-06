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
* **Language:** Go 1.20+\
**Other Libraries:**
* **NIST Control(s) Framework:** OSCAL (inspired)
* **Compliance Engine:** Custom Go modules parsing OSCAL-formatted regulatory documents
* **Report Generation:** PDF generation with wkhtmltopdf
# Getting Started
## *Prerequisites*
* Go 1.20+
## Where to launch ANISTAS
Navigate to the project folder and execute launcher.exe.
This action will initiate all the project components.
Subsequently, a PDF document containing the audit findings will be produced.
## Where to access the report
The report will be located in the project folder under the name "compliance-report-[report_id].pdf".
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
