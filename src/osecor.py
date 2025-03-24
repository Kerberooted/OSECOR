
import argparse
import requests
import json
import subprocess
import re
import os
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def strip_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

SUPPORTED_FORMATS = ["json", "csv", "html", "txt"]

def validate_output_format(output_format, filename):
    if not filename:
        return True
    ext = filename.split(".")[-1].lower()
    if ext != output_format:
        print(f"Error: Improper file type specified in -f '{filename}' for -o '{output_format}'")
        print(f"Did you mean: -f {filename.rsplit('.', 1)[0]}.{output_format} ?")
        exit(1)
    return True

def get_default_filename(url, file_format):
    domain = urlparse(url).netloc.replace("www.", "").split(":")[0]
    domain = domain.split(".")[0]
    return f"{domain}_osecor.{file_format}"

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

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

def check_ssl_tls(domain):
    try:
        response = requests.get(f"https://api.ssllabs.com/api/v3/analyze?host={domain}&publish=off&all=done")
        data = response.json()
        grade = data.get("endpoints", [{}])[0].get("grade", "F")
        grade_scores = {"A+": 100, "A": 95, "B": 80, "C": 60, "D": 40, "E": 20, "F": 0}
        return grade_scores.get(grade, 0), grade
    except Exception as e:
        return 0, f"Error: {e}"

def run_wafw00f_scan(target_url):
    try:
        result = subprocess.run(
            ["wafw00f", target_url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            return f"WAFW00F error (code {result.returncode}): {result.stderr.strip()}", 0
        output_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        for line in output_lines:
            if "is behind" in line:
                return strip_ansi_codes(line), 100
        return "No WAF detected", 0
    except Exception as e:
        return f"Unexpected Exception: {e}", 0

def run_zap_scan(target_url):
    try:
        zap_api_key = os.getenv("ZAP_API_KEY", "changeme")
        zap_url = "http://localhost:8080/JSON/ascan/action/scan"
        payload = {"url": target_url, "apikey": zap_api_key}
        response = requests.post(zap_url, params=payload)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def run_nuclei_scan(target_url):
    try:
        output = subprocess.check_output(["nuclei", "-u", target_url], stderr=subprocess.STDOUT, text=True)
        findings = re.findall(r"\[.*?\] (.*?) \n", output)
        score_deduction = len(findings) * 10
        return max(0, 100 - score_deduction), findings
    except Exception as e:
        return 100, f"Error: {e}"

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

def enumerate_subdomains(domain):
    try:
        output = subprocess.check_output(["subfinder", "-d", domain, "-silent"], text=True).strip()
        subdomains = output.splitlines()
        return max(0, 100 - len(subdomains) * 2), subdomains
    except Exception as e:
        return 100, f"Error: {e}"

def calculate_final_score(scores):
    return sum(scores) // len(scores)

def main():
    parser = argparse.ArgumentParser(description="Web Security Score Calculator with Output Support")
    parser.add_argument("url", help="Target website URL (e.g., https://example.com)")
    parser.add_argument("-o", "--output", required=True, choices=SUPPORTED_FORMATS, help="Output format")
    parser.add_argument("-f", "--filename", help="Custom output filename (optional)")
    args = parser.parse_args()

    url = args.url
    out_format = args.output.lower()
    out_file = args.filename or get_default_filename(url, out_format)

    validate_output_format(out_format, out_file)

    print(f"Scanning {url}...")

    sec_headers_score, missing_headers = check_security_headers(url)
    print(f"Security Headers Score: {sec_headers_score}/100")

    domain = url.split("//")[-1].split("/")[0]
    ssl_score, ssl_result = check_ssl_tls(domain)
    print(f"SSL/TLS Security Score: {ssl_score}/100 (Grade: {ssl_result})")

    nuclei_score, nuclei_results = run_nuclei_scan(url)
    print(f"Nuclei Scan Score: {nuclei_score}/100")

    zap_scan_results = run_zap_scan(url)
    zap_score = 80 if "error" not in zap_scan_results else 100
    print(f"ZAP Scan Score: {zap_score}/100")

    auth_score, auth_results = check_authentication_security(url)
    print(f"Authentication Security Score: {auth_score}/100")

    cms_score, cms_results = check_cms_version(url)
    print(f"CMS Version Security Score: {cms_score}/100")

    subdomain_score, subdomain_results = enumerate_subdomains(domain)
    print(f"Subdomain Security Score: {subdomain_score}/100")

    waf_detected, waf_score = run_wafw00f_scan(url)
    print(f"WAF Detected: {waf_detected}")

    final_score = calculate_final_score([
        sec_headers_score, ssl_score, nuclei_score, zap_score,
        auth_score, cms_score, subdomain_score, waf_score
    ])
    print(f"Final Security Score: {final_score}/100")

    results = {
        "url": url,
        "security_headers_score": sec_headers_score,
        "missing_security_headers": missing_headers,
        "ssl_score": ssl_score,
        "ssl_grade": ssl_result,
        "waf_detected": waf_detected,
        "vulnerability_scan_scores": {
            "Nuclei": nuclei_score,
            "ZAP": zap_score
        },
        "authentication_security_score": auth_score,
        "cms_security_score": cms_score,
        "detected_cms": cms_results,
        "subdomain_security_score": subdomain_score,
        "subdomains_found": subdomain_results,
        "waf_security_score": waf_score,
        "final_security_score": final_score
    }

    with open(out_file, "w") as f:
        if out_format == "json":
            json.dump(results, f, indent=4)
        elif out_format == "txt":
            for k, v in results.items():
                f.write(f"{k}: {v}\n")
        elif out_format == "csv":
            import csv
            flat = [(k, json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in results.items()]
            writer = csv.writer(f)
            writer.writerow(["Metric", "Value"])
            writer.writerows(flat)
        elif out_format == "html":
            f.write("<html><head><title>OSECOR Report</title></head><body><h1>Security Report</h1><ul>")
            for k, v in results.items():
                f.write(f"<li><strong>{k}:</strong> {v}</li>")
            f.write("</ul></body></html>")

    print(f"Security scan completed. Output saved to '{out_file}'.")

if __name__ == "__main__":
    main()
