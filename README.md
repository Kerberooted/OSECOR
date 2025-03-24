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

WAF Detection  
Uses WAFW00F to detect Web Application Firewalls and reports vendor information.  
Detected WAFs improve the final security score positively.

Final Security Score Calculation  
Uses a deterministic scoring algorithm to provide a clear, quantifiable security rating.  
Generates structured reports in JSON, HTML, CSV, and TXT formats.



## Use Cases

OSECOR is designed to support:

Security Engineers – Measure and track web security posture over time.

Developers – Identify missing security best practices before deployment.

IT & DevSecOps Teams – Integrate with CI/CD pipelines for continuous security testing.

Penetration Testers & Bug Hunters – Automate reconnaissance and vulnerability assessment.



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



## Running OSECOR

Windows - Open Command Terminal or Powershell ( Run either as Administrator)
Linux - Open Root Terminal

Navigate (cd) to where osecor.py is downloaded

Run this command to execute osecor: 

### Required Command to execute the tool
Linux - python3 osecor.py https://example.com -o filetype
Windows - python.exe osecor.py https://example.com -o filetype

Replace https://example.com with the target website URL.

![OSECOR CLI Execution](https://github.com/Kerberooted/OSECOR/blob/main/examples/proper-use.PNG?raw=true)

### Optional command to specify the filename for organization
python3 osecor.py https://example.com -o filetype -f filename
python.exe osecor.py https://example.com -o filetype -f filename

Replace filetype with csv, html, json, or txt to specify the required document form (i.e. "... -o html)
Replace filename after the -f flag to specify a unique filename (i.e. "... -o txt -f custom_name.txt")

If the '-f' flag is not used the tool will automatically generate the results to a document named after the domain that was scanned
Multiple scans of the same website using the same '-o' flag and without a '-f' flag will result in each previous scan of that website being overwritten. To prevent this, it is recommended to use the '-f' flag and specify the filename you want to save.

### Improper Usage Example

![OSECOR CLI Execution](https://github.com/Kerberooted/OSECOR/blob/main/examples/improper-use.png?raw=true)

### Proper Command-Line Usage Example

![OSECOR CLI Execution](https://github.com/Kerberooted/OSECOR/blob/main/examples/proper-use.PNG?raw=true)


## Viewing Security Report

Reports will be saved to the same directory that the osecor program was installed and/or executed.
### CSV
![OSECOR JSONOutput](https://github.com/Kerberooted/OSECOR/blob/main/examples/osecor-csv.PNG?raw=true)

### HTML
![OSECOR JSONOutput](https://github.com/Kerberooted/OSECOR/blob/main/examples/osecor-html.PNG?raw=true)

### JSON
![OSECOR JSONOutput](https://github.com/Kerberooted/OSECOR/blob/main/examples/osecor-json.PNG?raw=true)

### TXT

![OSECOR JSONOutput](https://github.com/Kerberooted/OSECOR/blob/main/examples/osecor-txt.PNG?raw=true)


## Future Roadmap (Non-exhaustive)

GUI Version – A GUI for improved usability and user experience.

CI/CD Integration – Automate security scoring within development pipelines.

Customizable Scoring Metrics – Allow users to adjust risk weights.

Machine Learning Integration – Improve risk assessment through AI-driven analysis.

More complex vulnerability assessment for a more detailed analysis and remediation recommendations.


## Contributing

Contributions are welcome. If you have suggestions or improvements, please fork the repository and submit a pull request. Adhere to the existing code structure and ensure any modifications align with OSECOR's goals.


## License

OSECOR is licensed under the GNU General Public License v3.0 (GPL-3.0).
You are free to use, modify, and distribute this tool as long as any derivative works remain under the same license and credit the original authors.


## Credits & Acknowledgments

This project leverages contributions from several open-source security tools:

OWASP ZAP – Automated vulnerability scanning

Nuclei – Template-based security scanning

Subfinder – Subdomain enumeration

SSL Labs API – SSL/TLS security evaluation

Wafw00f - WAF identifier


Thanks to the open-source security community and penetration testing researchers whose work has inspired and contributed to this project.
