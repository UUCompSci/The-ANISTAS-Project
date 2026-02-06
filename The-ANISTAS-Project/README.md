# The-ANISTAS-Project: Automated NIST Auditing System
A Go-based tool for automating the compliance process for NIST SP 800–171 on nonfederal information systems.

## Table of Contents
* About
* Features
* Tech Stack
* Getting Started
* Usage
* Project Status & Roadmap
* License

## About
ANISTAS (Automated NIST Auditing System) simplifies the NIST SP 800–171 auditing process for FTP/FPTS on Windows systems.
The project currently only focuses on IIS-hosted FTP/FTPS service(s), evaluating the key controls from SP 800–171,
and generating a PDF report containing the audit findings, and remediation recommendations.

The system is implemented as a set of gRPC microservices, an orchestrator, and a launcher to run it all. 
The microservices are split into three parts:\
Diagnostic service – for system health checks \
Audit service – for auditing the system\
Report service – for generating the report\
The Orchestrator is responsible for allowing these services to talk to one another.\
The launcher is responsible for launching the whole project.


## Features
* **Automated Windows FTP/FTPS auditing**
    * Gathers system information using a PowerShell script executed with elevated privileges.
* **NIST SP 800-171 Control Evaluation**
    * Evaluates the system against the NIST SP 800–171 controls.
    * 3.13.8 – Cryptographic protection during transmission of information.
    * 3.13.11 – Use of FIPS-validated cryptography.
    * 3.5.1 – Authentication and access control policies.
* Produces findings with control ID, description, severity, rationale, and remediation.

* **PDF Report Generation**
    * Generates a PDF report containing the audit findings and remediation recommendations.

## Tech Stack
* **Language:** Go 1.20+\
**Core Frameworks and Libraries:**
  * **gRPC:** gRPC is for inter-service communication.
  * **Protobuf:** for message and service definitions.
  * **wkhtmltopdf:** for PDF report generation.
  * **PowerShell:** for system information gathering.
  * **golang.org/x/sys/windows:** for Windows process attributes and ShellExecute-based elevation.

* **Reporting and Compliance Framework:**
* NIST SP 800-171 control modeling
* OWASP inspired fields for upload and authentication
# Getting Started
## *Prerequisites*
* Go 1.20+
* MUST BE RUN AS ADMINISTRATOR
## Where to launch ANISTAS
Navigate to the project folder and execute launcher.exe.
This action will initiate all the project components.
Subsequently, a PDF document containing the audit findings will be produced.
## Where to access the report
The report will be located in the project folder under the name "compliance-report-[report_id].pdf."
## *CLI Cloning*
```
# Clone repo
$ git clone https://github.com/UUCompSci/The-ANISTAS-Project.git 
$ cd anistas # Build
$ go build -o anistas ./cmd/audit-cli 
# Run a sample audit 
$ ./anistas audit --config testdata/sample_system.yaml
```
## Project Status & Roadmap
The ANISTAS project is currently under development. It is in its very beginning stages working. 
It focuses on one concrete case scenario for testing. 
* **Future:** 
* Add support for other operating systems.
* Add support for more SP 800–171 controls.
* Add support for other compliance frameworks. Including more NIST control frameworks.
* Extending support for the OWASP framework. 
* Adding a UI for the project likely fyre.
* Making the installation smoother/upgrading the story.
## Licence
MIT License

## Author
Eston Yandell
