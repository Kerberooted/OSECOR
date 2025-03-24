# OSECOR - Obelisk Web Security Core Assessment

## Overview

The Obelisk Web Security Core Assessment (OSECOR) is an advanced web application security posture scoring tool designed for security professionals, penetration testers, and developers. By integrating some of the most powerful and widely used web security tools into a single streamlined assessment, OSECOR provides a quantifiable, graded security score (0-100%) based on key security factors. This helps users efficiently identify, measure, and improve the security of their web applications.

This release (v1) is a CLI-based tool that performs multi-layered security assessments that combine automated scanning techniques, leveraging industry standard tools such as OWASP ZAP, Nuclei, and Subfinder. A GUI version (v2) is planned for a future release, allowing users to choose between command-line and graphical interfaces for convenience.



## Features

Security Headers Analysis

Detects missing HTTP security headers such as CSP, HSTS, X-Frame-Options, and more.

Assigns negative points for missing or misconfigured headers.

SSL/TLS Security Assessment

Uses SSL Labs API to evaluate SSL/TLS configurations.

Identifies weak ciphers, outdated TLS versions, and assigns an overall security grade.

Active Vulnerability Scanning

Integrates OWASP ZAP and Nuclei to scan for XSS, SQLi, LFI, RCE, and other vulnerabilities.

Parses results and assigns scores based on CVSS scoring.

Authentication & Session Security Checks

Examines session security controls, secure cookies, HTTP-only flags, and MFA presence.

CMS & Technology Stack Enumeration

Detects outdated WordPress, Joomla, and Drupal versions.

Identifies potential misconfigurations and assigns risk scores.

Subdomain & Exposure Analysis

Uses Subfinder to identify exposed subdomains.

Checks for open directories, admin panels, and exposed assets.

Final Security Score Calculation

Uses a deterministic scoring algorithm to provide a clear, quantifiable security rating.

Generates structured JSON reports for further analysis.



## Use Cases

OSECOR is designed to support:

Penetration Testers & Bug Hunters – Automate reconnaissance and vulnerability assessment.

Security Engineers – Measure and track web security posture over time.

Developers – Identify missing security best practices before deployment.

IT & DevSecOps Teams – Integrate with CI/CD pipelines for continuous security testing.



## Installation

### Windows Installation

Download the osecor.zip file or use git clone to clone the repository.

Install the latest version of Python (if not already installed): [Download Python](https://www.python.org/downloads/)

Install dependencies:
pip install requests beautifulsoup4 --user

Install OWASP ZAP, Nuclei, and Subfinder:
OWASP ZAP: [Download](https://www.zaproxy.org/download/)

Nuclei & Subfinder:
[Download](https://www.github.com/projectdiscovery/nuclei/releases)
[Download](https://www.github.com/projectdiscovery/subfinder/releases)

Ensure these tools are in your PATH or use full paths when running commands. 
- Additionally you can set it globally for your user's account:

pip install --user 'dependencies'

### Linux Installation

Download the osecor.zip file or use git clone to clone the repository.

Install the latest version of Python is installed (if not already installed): 

sudo apt install python3 python3-pip -y

Install required Python libraries:
pip install requests beautifulsoup4

Install OWASP ZAP, Nuclei, and Subfinder:
sudo apt install zaproxy -y

For Nuclei & Subfinder, install via ProjectDiscovery:
[Download](https://github.com/projectdiscovery/nuclei.git)
[Download](https://github.com/projectdiscovery/subfinder.git)

Ensure Nuclei and Subfinder are in your PATH:
export PATH=$HOME/.local/bin:$PATH


### Running OSECOR

Open command terminal ( Run as Administrator)

navigate to where osecor.py is downloaded

Run this command to execute osecor: 

Linux - python3 osecor.py https://example.com
Windows - python.exe osecor.py https://example.com

Replace https://example.com with the target website URL.

![OSECOR CLI Execution](https://github.com/Kerberooted/OSECOR/blob/main/examples/osecor-cli.PNG)

### Viewing Security Report
cat security_report.json

![OSECOR JSONOutput](https://github.com/Kerberooted/OSECOR/blob/main/examples/osecor-json.PNG)


## Future Roadmap

GUI Version (v2) – A GUI for improved usability.

CI/CD Integration – Automate security scoring within development pipelines.

Customizable Scoring Metrics – Allow users to adjust risk weights.

Machine Learning Integration – Improve risk assessment through AI-driven analysis.



## Contributing

Contributions are welcome. If you have suggestions or improvements, please fork the repository and submit a pull request. Adhere to the existing code structure and ensure any modifications align with OSECOR's goals.



## License

OSECOR is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.  
You are free to use, modify, and distribute this tool as long as any derivative works remain under the same license and credit the original authors.


## Credits & Acknowledgments

This project leverages contributions from several open-source security tools:

OWASP ZAP – Automated vulnerability scanning

Nuclei – Template-based security scanning

Subfinder – Subdomain enumeration

SSL Labs API – SSL/TLS security evaluation

Thanks to the open-source security community and penetration testing researchers whose work has inspired and contributed to this project.
