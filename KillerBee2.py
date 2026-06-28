import subprocess
import sys
import whois
import requests
import socket
import os
import getpass
from colorama import Fore, Style, init

init(autoreset=True)

model = None
sudo_pass = None

def setup_gemini():
    global model
    try:
        import google.generativeai as genai
        use_gemini = input(Fore.YELLOW + "[?] Do you want to use Gemini AI? (y/n): ").strip().lower()
        if use_gemini == 'y':
            api_key = input(Fore.YELLOW + "[+] Enter your Gemini API key: ")
            model_name = input(Fore.YELLOW + "[+] Enter Gemini model name (e.g., gemini-1.5-flash): ")
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel(model_name)
            print(Fore.GREEN + "[+] Gemini AI initialized successfully.")
        else:
            model = None
    except Exception as e:
        print(Fore.RED + f"[!] Failed to initialize Gemini: {e}")
        model = None

def setup_sudo():
    global sudo_pass
    sudo_pass = getpass.getpass(Fore.YELLOW + "[!] Enter your sudo password for privileged operations: ")

def run_command(cmd_list):
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(Fore.RED + result.stderr)
    except FileNotFoundError:
        print(Fore.RED + f"[-] Command not found: {cmd_list[0]}. Is it installed?")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

def run_sudo_cmd(cmd_list):
    try:
        result = subprocess.run(
            ['sudo', '-S'] + cmd_list,
            input=sudo_pass + '\n',
            text=True,
            capture_output=True
        )
        if result.stdout:
            print(result.stdout)
        if result.stderr and 'sudo' not in result.stderr.lower():
            print(Fore.RED + result.stderr)
    except FileNotFoundError:
        print(Fore.RED + f"[-] Command not found: {cmd_list[0]}. Is it installed?")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

def is_tool_installed(tool):
    result = subprocess.run(["which", tool], capture_output=True, text=True)
    return result.returncode == 0

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
    if not is_tool_installed("nslookup"):
        print(Fore.RED + "[-] nslookup not installed.")
        return
    run_command(["nslookup", domain])

def reverse_ip():
    ip = input("Enter IP: ")
    if not is_tool_installed("host"):
        print(Fore.RED + "[-] host command not installed.")
        return
    run_command(["host", ip])

def subdomain_finder():
    domain = input("Enter domain: ")
    if not os.path.isfile("subdomains.txt"):
        print(Fore.RED + "[-] subdomains.txt not found in current directory!")
        return
    with open("subdomains.txt") as f:
        subs = f.read().splitlines()
    print(Fore.YELLOW + f"[*] Scanning {len(subs)} subdomains for {domain}...\n")
    found = 0
    for sub in subs:
        if not sub.strip():
            continue
        full = f"{sub.strip()}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            print(Fore.GREEN + f"[+] {full} -> {ip}")
            found += 1
        except socket.gaierror:
            pass
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Scan interrupted by user.")
            break
    print(Fore.CYAN + f"\n[*] Done. Found {found} subdomains.")

def email_harvest():
    domain = input("Enter domain: ")
    print(Fore.YELLOW + f"[*] For email harvesting on {domain}, use:")
    print(Fore.CYAN + f"    theHarvester -d {domain} -b all")
    print(Fore.CYAN + f"    Or visit: https://hunter.io/search/{domain}")

def ip_geolocation():
    ip = input("Enter IP: ")
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        r.raise_for_status()
        data = r.json()
        for key, value in data.items():
            print(Fore.GREEN + f"  {key:<12}: {value}")
    except requests.exceptions.Timeout:
        print(Fore.RED + "[-] Request timed out.")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[-] Request failed: {e}")

# Scanning Tools

def nmap_scan():
    if not is_tool_installed("nmap"):
        print(Fore.RED + "[-] nmap not installed. Run: sudo apt install nmap")
        return
    target = input("Enter target IP/domain: ")
    print(Fore.YELLOW + f"[*] Running Nmap SYN scan on {target}...")
    run_sudo_cmd(['nmap', '-sS', '-T4', target])

def masscan_scan():
    if not is_tool_installed("masscan"):
        print(Fore.RED + "[-] masscan not installed. Run: sudo apt install masscan")
        return
    target = input("Enter IP: ")
    print(Fore.YELLOW + f"[*] Running Masscan on {target} (ports 1-1000)...")
    run_sudo_cmd(['masscan', target, '-p1-1000', '--rate=1000'])

def tcping_scan():
    if not is_tool_installed("tcping"):
        print(Fore.RED + "[-] tcping not installed.")
        print(Fore.YELLOW + "[*] Install: sudo apt install tcping  (or use ncat/nmap for TCP checks)")
        return
    host = input("Enter host: ")
    port = input("Port (default 80): ").strip() or "80"
    run_command(["tcping", host, port])

def nikto_scan():
    if not is_tool_installed("nikto"):
        print(Fore.RED + "[-] nikto not installed. Run: sudo apt install nikto")
        return
    url = input("Enter target URL: ")
    run_command(["nikto", "-h", url])

def curl_status():
    if not is_tool_installed("curl"):
        print(Fore.RED + "[-] curl not installed.")
        return
    url = input("Enter URL: ")
    run_command(["curl", "-I", url])

def openvas_scan():
    print(Fore.YELLOW + "[*] OpenVAS requires external setup.")
    print(Fore.CYAN + "    Install: sudo apt install openvas")
    print(Fore.CYAN + "    Setup:   sudo gvm-setup")
    print(Fore.CYAN + "    Start:   sudo gvm-start")

def main_menu():
    print_banner()
    setup_gemini()
    setup_sudo()

    while True:
        print_banner()
        print(Fore.CYAN + """
[1] Footprinting Tools
[2] Scanning Tools
[3] Ask Gemini
[4] Exit
""")
        choice = input("Choice: ").strip()

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
            tool = input("Select: ").strip()
            tools = {
                '1': whois_lookup,
                '2': dns_lookup,
                '3': reverse_ip,
                '4': subdomain_finder,
                '5': email_harvest,
                '6': ip_geolocation
            }
            if tool == '7':
                continue
            action = tools.get(tool)
            if action:
                action()
            else:
                print(Fore.RED + "[-] Invalid choice.")

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
            tool = input("Select: ").strip()
            tools = {
                '1': nmap_scan,
                '2': masscan_scan,
                '3': tcping_scan,
                '4': nikto_scan,
                '5': curl_status,
                '6': openvas_scan
            }
            if tool == '7':
                continue
            action = tools.get(tool)
            if action:
                action()
            else:
                print(Fore.RED + "[-] Invalid choice.")

        elif choice == '3':
            ask_gemini()

        elif choice == '4':
            print(Fore.GREEN + "[*] Exiting Killer Bee. Stay Safe!")
            sys.exit(0)

        else:
            print(Fore.RED + "[-] Invalid choice.")

if __name__ == "__main__":
    main_menu()
