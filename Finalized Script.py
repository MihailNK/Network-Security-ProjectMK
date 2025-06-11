import requests
import urllib3
import json
import datetime
import re
import sys

# Disable SSL warnings for self-signed certificates.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG_FILE = "sophos_firewall_audit.log"

def log_output(title, output):
    """Log output to console and file with headers."""
    log_entry = f"\n[=== {title} ===]\n{output}\n[=== END {title} ===]\n"
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

def check_password_requirements(password):
    """Check that password meets the basic requirements."""
    # At least 12 characters long
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    # At least one uppercase letter
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    # At least one lowercase letter
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    # At least one digit
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    # Any non-alphanumeric character qualifies as special
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one special character."
    return True, ""

class SophosXGAPI:
    def __init__(self, host, username, password):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        # Construct the base REST API endpoint.
        self.base_url = f"https://{self.host}:4444/webconsole/APIController"
        # Create a session with certificate verification disabled.
        self.session = requests.Session()
        self.session.verify = False
        self.session.auth = (username, password)

    def call_api(self, params, method="GET", data=None):
        """Generic method for calling the Sophos API."""
        try:
            if method.upper() == "GET":
                response = self.session.get(self.base_url, params=params, timeout=10)
            else:
                response = self.session.post(self.base_url, params=params, json=data, timeout=10)
            response.raise_for_status()
            # Check if the response indicates an access restriction (status code 534).
            if "Status code=\"534\"" in response.text:
                error_message = ("API operations are not allowed from the requester IP address. "
                                 "Please check the firewall's API whitelist configuration.")
                log_output("API Error", f"Params: {params}\nError: {error_message}")
                return {"error": error_message}
            try:
                return response.json()
            except Exception:
                return response.text
        except Exception as e:
            log_output("API Error", f"Params: {params}\nError: {str(e)}")
            return None

    def get_network_interfaces(self):
        params = {"req": "GetNetworkInterfaces"}
        return self.call_api(params)

    def set_system_banner(self, banner_text):
        params = {"req": "SetSystemBanner"}
        data = {"banner": banner_text}
        return self.call_api(params, method="POST", data=data)

    def disable_service(self, service_name):
        params = {"req": "DisableService"}
        data = {"service": service_name}
        return self.call_api(params, method="POST", data=data)

    def set_password_policy(self, policy):
        params = {"req": "SetPasswordPolicy"}
        data = policy
        return self.call_api(params, method="POST", data=data)

    def set_dos_protection(self, dos_type, enable=True):
        params = {"req": "SetDoSProtection"}
        data = {"type": dos_type, "enable": enable}
        return self.call_api(params, method="POST", data=data)

    def get_password_policy(self):
        params = {"req": "GetPasswordPolicy"}
        return self.call_api(params)

    def get_system_banner(self):
        params = {"req": "GetSystemBanner"}
        return self.call_api(params)

    def get_dos_protection_status(self):
        params = {"req": "GetDoSProtectionStatus"}
        return self.call_api(params)

def main():
    host = "*"  # Change to your firewall's IP address
    username = "*"     # Your username
    password = "*"  # Your current admin password

    valid, message = check_password_requirements(password)
    if not valid:
        log_output("Password Requirement Error", message)
        sys.exit(1)
    else:
        log_output("Password Check", "Password meets the required criteria.")

    fw = SophosXGAPI(host, username, password)

    # ------------------ Audit Network Interfaces ------------------
    log_output("Audit Step (API)", "Auditing Network Interfaces...")
    interfaces = fw.get_network_interfaces()
    log_output("Interfaces List (API)", json.dumps(interfaces, indent=2))

    # ------------------ Set System Banner ------------------
    log_output("Security Step (API)", "Setting System Banner via API...")
    banner_text = "Authorized access only. Violators will be prosecuted."
    banner_result = fw.set_system_banner(banner_text)
    log_output("Banner Applied (API)", json.dumps(banner_result, indent=2))

    # ------------------ Disable Unused Services ------------------
    log_output("Security Step (API)", "Disabling unused services via API...")
    services = ["cdp", "proxy-arp", "web-management-http", "ip-source-routing"]
    disable_results = {}
    for service in services:
        disable_results[service] = fw.disable_service(service)
    log_output("Disabled Services (API)", json.dumps(disable_results, indent=2))

    # ------------------ Enable Password Policy ------------------
    log_output("Security Step (API)", "Enabling Password Policy via API...")
    policy = {
        "minimum_length": 12,
        "complexity": True,
        "expire_days": 90,
        "lockout_threshold": 5,
    }
    policy_result = fw.set_password_policy(policy)
    log_output("Password Policy Set (API)", json.dumps(policy_result, indent=2))

    # ------------------ Configure DoS Protections ------------------
    log_output("Security Step (API)", "Configuring DoS protections via API...")
    dos_results = {}
    dos_types = ["syn-flood", "port-scan", "smurf", "icmp-flood"]
    for dos in dos_types:
        dos_results[dos] = fw.set_dos_protection(dos, True)
    log_output("DoS Protection (API)", json.dumps(dos_results, indent=2))

    # ------------------ Validate Security Settings ------------------
    log_output("Validation Step (API)", "Validating Security Settings via API...")
    current_policy = fw.get_password_policy()
    current_banner = fw.get_system_banner()
    current_dos_status = fw.get_dos_protection_status()
    validation = {
        "password_policy": current_policy,
        "banner": current_banner,
        "dos_protection_status": current_dos_status,
    }
    log_output("Validation (API)", json.dumps(validation, indent=2))

if __name__ == "__main__":
    start_time = datetime.datetime.now()
    print(f"[+] Script started at {start_time.strftime('%H:%M:%S')}")
    main()
    end_time = datetime.datetime.now()
    print(f"[+] Script ended at {end_time.strftime('%H:%M:%S')}")
