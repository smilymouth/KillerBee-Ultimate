import subprocess
import sys
import whois
import requests
import socket
import os
import getpass
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Optional Gemini AI Setup
try:
    import google.generativeai as genai
    use_gemini = input(Fore.YELLOW + "[?] Do you want to use Gemini AI? (y/n): ").strip().lower()
    if use_gemini == 'y':
        api_key = input(Fore.YELLOW + "[+] Enter your Gemini API key: ")
        model_name = input(Fore.YELLOW + "[+] Enter Gemini model name (e.g., gemini-1.5-flash): ")
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
    else:
        model = None
except Exception as e:
    print(Fore.RED + f"[!] Failed to initialize Gemini: {e}")
    model = None

# Ask for sudo password once
sudo_pass = getpass.getpass(Fore.YELLOW + "[!] Enter your sudo password for privileged operations: ")

def print_banner():
    print(Fore.MAGENTA + """
██╗  ██╗██╗██╗     ██╗     ███████╗██████╗     ██████╗ ███████╗███████╗
██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝
█████╔╝ ██║██║     ██║     █████╗  ██████╔╝    ██████╔╝█████╗  █████╗
██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗    ██╔══██╗██╔══╝  ██╔══╝
██║  ██╗██║███████╗███████╗███████╗██║  ██║    ██████╔╝███████╗███████╗
╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚══════╝╚══════╝
                      🐝 Killer Bee Ultimate 🐝
""" + Style.RESET_ALL)

def ask_gemini():
    if model is None:
        print(Fore.YELLOW + "[*] Gemini AI is disabled or not configured.")
        return
    question = input(Fore.CYAN + "[+] Ask Gemini AI: ")
    try:
        response = model.generate_content(question)
        print(Fore.GREEN + response.text)
    except Exception as e:
        print(Fore.RED + f"[-] Gemini Error: {e}")

# Footprinting Tools

def whois_lookup():
    domain = input("Enter domain: ")
    try:
        info = whois.whois(domain)
        print(info)
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

def dns_lookup():
    domain = input("Enter domain: ")
    os.system(f"nslookup {domain}")

def reverse_ip():
    ip = input("Enter IP: ")
    os.system(f"host {ip}")

def subdomain_finder():
    domain = input("Enter domain: ")
    if not os.path.isfile("subdomains.txt"):
        print(Fore.RED + "[-] subdomains.txt missing!")
        return
    with open("subdomains.txt") as f:
        subs = f.read().splitlines()
    for sub in subs:
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            print(Fore.GREEN + f"[+] {full} -> {ip}")
        except:
            pass

def email_harvest():
    domain = input("Enter domain: ")
    print(Fore.YELLOW + "[*] Simulated: Use tools like theHarvester or hunter.io")

def ip_geolocation():
    ip = input("Enter IP: ")
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json")
        print(r.json())
    except Exception as e:
        print(Fore.RED + str(e))

# Scanning Tools

def run_sudo_cmd(cmd):
    return subprocess.run(['sudo', '-S'] + cmd, input=sudo_pass + '\n', text=True, capture_output=True)

def nmap_scan():
    target = input("Enter target IP/domain: ")
    result = run_sudo_cmd(['nmap', '-sS', '-T4', target])
    print(result.stdout)

def masscan_scan():
    target = input("Enter IP: ")
    result = run_sudo_cmd(['masscan', target, '-p1-1000', '--rate=1000'])
    print(result.stdout)

def tcping_scan():
    host = input("Enter host: ")
    port = input("Port (default 80): ") or "80"
    os.system(f"tcping {host} {port}")

def nikto_scan():
    url = input("Enter target URL: ")
    os.system(f"nikto -h {url}")

def curl_status():
    url = input("Enter URL: ")
    os.system(f"curl -I {url}")

def openvas_scan():
    print(Fore.YELLOW + "[*] OpenVAS setup required externally.")

def main_menu():
    while True:
        print_banner()
        print(Fore.CYAN + """
[1] Footprinting Tools
[2] Scanning Tools
[3] Ask Gemini
[4] Exit
""")
        choice = input("Choice: ")

        if choice == '1':
            print(Fore.BLUE + """
[1] WHOIS Lookup
[2] DNS Lookup
[3] Reverse IP Lookup
[4] Subdomain Finder
[5] Email Harvesting
[6] IP Geolocation
[7] Back to Main Menu
""")
            tool = input("Select: ")
            tools = {
                '1': whois_lookup,
                '2': dns_lookup,
                '3': reverse_ip,
                '4': subdomain_finder,
                '5': email_harvest,
                '6': ip_geolocation
            }
            if tool == '7': continue
            tools.get(tool, lambda: print("Invalid"))()

        elif choice == '2':
            print(Fore.BLUE + """
[1] Nmap Scan
[2] Masscan Scan
[3] TCPing Port Ping
[4] Nikto Web Scanner
[5] Curl HTTP Status Check
[6] OpenVAS Scan
[7] Back to Main Menu
""")
            tool = input("Select: ")
            tools = {
                '1': nmap_scan,
                '2': masscan_scan,
                '3': tcping_scan,
                '4': nikto_scan,
                '5': curl_status,
                '6': openvas_scan
            }
            if tool == '7': continue
            tools.get(tool, lambda: print("Invalid"))()

        elif choice == '3':
            ask_gemini()
        elif choice == '4':
            print(Fore.GREEN + "[*] Exiting Killer Bee. Stay Safe!")
            break
        else:
            print(Fore.RED + "Invalid choice")

if __name__ == "__main__":
    main_menu()
