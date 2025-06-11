# Network-Security-ProjectMihailNikolov

This project is a course assignment designed to automate the remote configuration of network devices/hosts.

Overview
The script/s is/are designed to:

Audit Network Interfaces: Retrieve and log network interface configurations.

Configure Security Settings:

Set a custom system banner.

Disable unused services (e.g., CDP, proxy-ARP, web management HTTP, IP source routing).

Enforce a strong password policy.

Configure DoS protections for common attack vectors.

Restrict management access (e.g., SSH restrictions).

Manage Firewall Rules: Create and update firewall rules (e.g., to block suspicious traffic).

Key Modifications for Sophos
Because the Sophos Firewall API behaves differently than many standard REST APIs, the following customizations were implemented:

Endpoint URL Override: The SDK normally constructs the API endpoint using the API version (e.g., generating a URL like https://<firewall-ip>:1905.1/webconsole/APIController). However, since the firewall’s admin console is configured to use port 4444, the code overrides the endpoint URL both at the class and instance levels so that all API requests target:

https://<firewall-ip>:4444/webconsole/APIController
Disabling SSL Certificate Verification: The firewall uses a self-signed certificate, which triggers SSL verification errors. For testing purposes only, SSL certificate verification is disabled through multiple approaches:

Setting the environment variable PYTHONHTTPSVERIFY=0

Overriding the default HTTPS context using ssl._create_unverified_context

Monkey-patching the requests.Session.request method to always use verify=False

!Disabling certificate verification is not recommended for production environments.

Requirements
Python 3.x

Sophos Firewall Python SDK Install via pip:

bash
pip install sophosfirewall-python
Usage
Configure API Credentials: Update the following variables in the script with your Sophos Firewall details:

API_HOST – Firewall IP address.

API_PORT – Admin console HTTPS port (e.g., 4444).

API_USERNAME – Your admin/API username.

API_PASSWORD – Your API password.

API_VERSION – Although used by the SDK internally, the endpoint override forces the URL to use the correct port.

Run the Script: Execute the script via the command line:

bash
python Finalized Script.py
The script will connect to your Sophos Firewall, execute audit and configuration tasks, and log output to both the console and a log file (sophos_firewall_audit_sdk.log).

License
This project is provided "as-is" without any warranty. Use and modify it for your internal testing and automation purposes as needed.

This README summarizes the purpose, key modifications, requirements, and usage instructions for the Sophos Firewall automation script. Feel free to adjust and expand on it to fit your documentation standards.
