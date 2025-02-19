# C0M3T5C4N - XSS Vulnerability Scanner, Auto-Exploiter & Destructive Payload Demonstrator

## Description
C0M3T5C4N is an automated security tool designed to hunt for Cross-Site Scripting (XSS) vulnerabilities in web applications. It scans for reflected, stored, and redirection-based XSS by injecting a wide variety of payloads into web forms. In addition to detecting vulnerabilities, C0M3T5C4N demonstrates exploitation by auto-executing payloads that simulate malicious behavior—ranging from benign alerts to full-page defacement and redirection. This tool not only shows how an attacker might compromise a vulnerable site, but also highlights the destructive potential of unsanitized inputs.

> **Warning:** The destructive payloads integrated into this tool can completely alter or deface a webpage, flood the interface with pop-ups, and redirect users away from the original content. **These actions are irreversible on a live target and should only be executed in controlled, authorized testing environments.**

## Features
- **Automated XSS Testing:** Injects a comprehensive set of payloads at low, medium, and high threat levels.
- **Multi-Process & Multi-Threaded Scanning:** Leverages multiprocessing and threading for efficient scanning of multiple URLs.
- **Wide Range of Payloads:** Tests for various types of XSS vulnerabilities including:
  - **Reflected XSS:** Payloads that echo back input values.
  - **Stored XSS:** Payloads that are designed to persist on the server (e.g., via form submissions).
  - **DOM-Based XSS:** Payloads that exploit client-side vulnerabilities.
  - **Redirection & Defacement:** Payloads that redirect the browser or completely deface the webpage by replacing its content.
  - **Destructive Actions:** Some payloads simulate severe exploitation by removing page content, overlaying custom messages, or initiating repeated alert floods.
- **Real-time Progress Display:** Provides colored terminal output and progress bars to track scanning status.
- **Vulnerability Reporting:** Logs detailed vulnerability information (URL, payload, threat level, exploitable input) to `XSS/vulns.txt` and exploited URLs to `XSS/exploit-url.txt`.
- **Flexible Scanning Options:** Choose to scan a single URL or perform a bulk scan from a file containing multiple URLs.
- **Platform-Specific Greetings:** Displays custom welcome messages, including a special greeting for Arch Linux users.

## Destructive Payloads and Their Effects
C0M3T5C4N includes several payloads that are inherently destructive when executed on vulnerable targets. These payloads serve as demonstrations of the potential impact of XSS attacks:
- **Full Page Defacement:** Replaces the entire webpage content with attacker-controlled messages or images. Payloads such as `deface_full_page` or `deface_overlay` can completely obscure the original site layout and content.
- **Redirection Attacks:** Automatically redirects users to external sites or malicious pages using JavaScript or meta refresh techniques.
- **Alert Flooding:** Repeatedly triggers alert pop-ups that can render a webpage unusable by flooding the interface.
- **Content Manipulation:** Alters the DOM to remove, replace, or overlay elements, effectively defacing the site and confusing end users.
- **Stored XSS Demonstrations:** Injects payloads that, if persisted, could affect every user who visits the compromised page.

These destructive capabilities are intended to help penetration testers understand the severity of XSS vulnerabilities. **Do not deploy these payloads on production systems without explicit authorization.**

## Installation
1. **Clone the Repository**:
   ```
   git clone https://github.com/your_username/c0m3t5c4n.git
   cd c0m3t5c4n```
2. **Install Requirements**:
   ```
   pip install -r requirements.txt --break-system-packages```
3. **Execute c0m3t5c4n**:
   ```
   python3 c0m3t5c4n.py```
   
# Main Menu Options:
    1. Check for XSS: Enter a single URL to scan for XSS vulnerabilities.
    2. Scan URLs from a File: Provide a file path containing URLs (one per line) for bulk scanning.
    3. Exit: Quit the application.

# Review the Results:
    1. Detected vulnerabilities are logged in XSS/vulns.txt.
    2. Exploited action URLs are saved in XSS/exploit-url.txt
