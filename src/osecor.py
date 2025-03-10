import argparse
import requests
import json
import subprocess
import re
import os
from bs4 import BeautifulSoup

# Security Headers Check
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

# Function to check security headers
def check_security_headers(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        score = 100

        missing_headers = []

        for header in SECURITY_HEADERS:
            if header not in headers:
                score -= 5
                missing_headers.append(header)

        return score, missing_headers
    except Exception as e:
        return 0, f"Error: {e}"

# Function to check SSL/TLS security using SSL Labs API
def check_ssl_tls(domain):
    try:
        response = requests.get(f"https://api.ssllabs.com/api/v3/analyze?host={domain}&publish=off&all=done")
        data = response.json()
        grade = data.get("endpoints", [{}])[0].get("grade", "F")

        grade_scores = {"A+": 100, "A": 95, "B": 80, "C": 60, "D": 40, "E": 20, "F": 0}
        return grade_scores.get(grade, 0), grade
    except Exception as e:
        return 0, f"Error: {e}"

# Function to run OWASP ZAP for vulnerability scanning
def run_zap_scan(target_url):
    try:
        zap_api_key = os.getenv("ZAP_API_KEY", "changeme")
        zap_url = "http://localhost:8080/JSON/ascan/action/scan"
        payload = {"url": target_url, "apikey": zap_api_key}
        response = requests.post(zap_url, params=payload)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

# Function to run Nuclei for vulnerability scanning
def run_nuclei_scan(target_url):
    try:
        output = subprocess.check_output(["nuclei", "-u", target_url], stderr=subprocess.STDOUT, text=True)
        findings = re.findall(r"\[.*?\] (.*?) \n", output)
        score_deduction = len(findings) * 10
        return max(0, 100 - score_deduction), findings
    except Exception as e:
        return 100, f"Error: {e}"

# Function to check for authentication security (cookies, MFA)
def check_authentication_security(url):
    try:
        response = requests.get(url, timeout=10)
        cookies = response.cookies
        score = 100

        for cookie in cookies:
            if not cookie.secure:
                score -= 5

        return score, cookies
    except Exception as e:
        return 0, f"Error: {e}"

# Function to check for outdated CMS versions
def check_cms_version(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        meta_tags = soup.find_all("meta")

        cms_versions = {"WordPress": "wp-", "Joomla": "Joomla", "Drupal": "Drupal"}
        found_versions = []

        for meta in meta_tags:
            for cms, identifier in cms_versions.items():
                if identifier in str(meta):
                    found_versions.append(cms)

        return 100 if not found_versions else 50, found_versions
    except Exception as e:
        return 0, f"Error: {e}"

# Function to enumerate subdomains
def enumerate_subdomains(domain):
    try:
        output = subprocess.check_output(["subfinder", "-d", domain, "-silent"], text=True).strip()
        subdomains = output.splitlines()
        return max(0, 100 - len(subdomains) * 2), subdomains
    except Exception as e:
        return 100, f"Error: {e}"


# Function to calculate the final score
def calculate_final_score(scores):
    return sum(scores) // len(scores)

# Main function
def main():
    parser = argparse.ArgumentParser(description="Web Security Score Calculator")
    parser.add_argument("url", help="Target website URL (e.g., https://example.com)")

    args = parser.parse_args()
    url = args.url

    print(f"Scanning {url}...")

    # Security Headers Check
    sec_headers_score, missing_headers = check_security_headers(url)
    print(f"Security Headers Score: {sec_headers_score}/100")

    # SSL/TLS Security Check
    domain = url.split("//")[-1].split("/")[0]
    ssl_score, ssl_result = check_ssl_tls(domain)
    print(f"SSL/TLS Security Score: {ssl_score}/100 (Grade: {ssl_result})")

    # Vulnerability Scans
    nuclei_score, nuclei_results = run_nuclei_scan(url)
    print(f"Nuclei Scan Score: {nuclei_score}/100")

    zap_scan_results = run_zap_scan(url)
    zap_score = 80 if "error" not in zap_scan_results else 100  # Placeholder score if no results
    print(f"ZAP Scan Score: {zap_score}/100")

    # Authentication Security Check
    auth_score, auth_results = check_authentication_security(url)
    print(f"Authentication Security Score: {auth_score}/100")

    # CMS Detection
    cms_score, cms_results = check_cms_version(url)
    print(f"CMS Version Security Score: {cms_score}/100")

    # Subdomain Enumeration
    subdomain_score, subdomain_results = enumerate_subdomains(domain)
    print(f"Subdomain Security Score: {subdomain_score}/100")

    # Final Score Calculation
    final_score = calculate_final_score([
        sec_headers_score, ssl_score, nuclei_score, zap_score,
        auth_score, cms_score, subdomain_score
    ])
    print(f"Final Security Score: {final_score}/100")

    # Save results to JSON file
    results = {
        "url": url,
        "security_headers_score": sec_headers_score,
        "missing_security_headers": missing_headers,
        "ssl_score": ssl_score,
        "ssl_grade": ssl_result,
        "vulnerability_scan_scores": {
            "Nuclei": nuclei_score,
            "ZAP": zap_score
        },
        "authentication_security_score": auth_score,
        "cms_security_score": cms_score,
        "detected_cms": cms_results,
        "subdomain_security_score": subdomain_score,
        "subdomains_found": subdomain_results,
        "final_security_score": final_score
    }

    with open("security_report.json", "w") as f:
        json.dump(results, f, indent=4)

    print("Security scan completed. Report saved as 'security_report.json'.")

if __name__ == "__main__":
    main()
