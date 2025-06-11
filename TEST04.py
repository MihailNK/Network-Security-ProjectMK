#!/usr/bin/env python3
"""
Sophos Firewall Automation and Audit Script
This script uses the Sophos Firewall Python SDK along with Jinja2-based templates
to perform audits, apply configuration changes (e.g. system banner, disable services,
set password policy, DoS protections, restrict management access), and create/update firewall rules.
Ensure that the 'sophosfirewall-python' package is installed:
    pip install sophosfirewall-python

XML templates are temporarily written into a local "templates" folder and deleted after use.
"""

import os
import sys
import time
import datetime
import re
import traceback
import ssl

ssl._create_default_https_context = ssl._create_unverified_context


# === API Connection Credentials ===
API_HOST = "172.16.44.54"  # Firewall IP address
API_PORT = "4444"  # Admin Console HTTPS Port (must match the firewall configuration)
API_USERNAME = "admin"  # Your API username
API_PASSWORD = "23belfat-Zfs"  # Insert your API password here
API_VERSION = "4444"  # Normally used by the SDK; we override the endpoint URL below

LOG_FILE = "sophos_firewall_audit_sdk.log"

# --- SDK IMPORTS ---
try:
    from sophosfirewall_python.firewallapi import SophosFirewall, SophosFirewallAPIError
    from sophosfirewall_python.utils import Utils
except ImportError as e:
    print("[!!!] FATAL ERROR: Failed to import Sophos Firewall SDK components.")
    print("Please ensure that the SDK is installed: 'pip install sophosfirewall-python'")
    sys.exit(1)

# *** OVERRIDE THE ENDPOINT URL AT THE CLASS LEVEL ***
# This override replaces the get_endpoint_url method so that every instance will use
# the URL built with API_HOST and API_PORT.
SophosFirewall.get_endpoint_url = lambda self: "https://{}:{}/webconsole/APIController".format(API_HOST, API_PORT)

# --- XML Templates as Strings (with XML Declaration) ---
SET_BANNER_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<Request APIVersion="2000.2">
  <Login>
    <Username>{{ username }}</Username>
    <Password>{{ password }}</Password>
  </Login>
  <Set operation="update">
    <System>
      <ConsoleBanner>{{ banner_text }}</ConsoleBanner>
    </System>
  </Set>
</Request>
"""

DISABLE_SERVICE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<Request APIVersion="2000.2">
  <Login>
    <Username>{{ username }}</Username>
    <Password>{{ password }}</Password>
  </Login>
  <Set operation="update">
    <System>
      {% if service == 'cdp' %}
      <Cdp>{{ 'Disable' if action == 'disable' else 'Enable' }}</Cdp>
      {% elif service == 'proxy-arp' %}
      <ProxyARP>{{ 'Disable' if action == 'disable' else 'Enable' }}</ProxyARP>
      {% elif service == 'web-management-http' %}
      <WebManagementHTTP>{{ 'Disable' if action == 'disable' else 'Enable' }}</WebManagementHTTP>
      {% elif service == 'ip-source-routing' %}
      <IpSourceRouting>{{ 'Disable' if action == 'disable' else 'Enable' }}</IpSourceRouting>
      {% endif %}
    </System>
  </Set>
</Request>
"""

SET_PASSWORD_POLICY_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<Request APIVersion="2000.2">
  <Login>
    <Username>{{ username }}</Username>
    <Password>{{ password }}</Password>
  </Login>
  <Set operation="update">
    <PasswordPolicy>
      <MinimumLength>{{ min_length }}</MinimumLength>
      <Complexity>{{ complexity }}</Complexity>
      <ExpireDays>{{ expire_days }}</ExpireDays>
      <LockoutThreshold>{{ lockout_threshold }}</LockoutThreshold>
    </PasswordPolicy>
  </Set>
</Request>
"""

SET_DOS_PROTECTION_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<Request APIVersion="2000.2">
  <Login>
    <Username>{{ username }}</Username>
    <Password>{{ password }}</Password>
  </Login>
  <Set operation="update">
    <DosProtection>
      {% if attack_type == 'syn-flood' %}
      <SynFlood>{{ 'Enable' if action == 'enable' else 'Disable' }}</SynFlood>
      {% elif attack_type == 'port-scan' %}
      <PortScan>{{ 'Enable' if action == 'enable' else 'Disable' }}</PortScan>
      {% elif attack_type == 'smurf' %}
      <Smurf>{{ 'Enable' if action == 'enable' else 'Disable' }}</Smurf>
      {% elif attack_type == 'icmp-flood' %}
      <IcmpFlood>{{ 'Enable' if action == 'enable' else 'Disable' }}</IcmpFlood>
      {% endif %}
    </DosProtection>
  </Set>
</Request>
"""

SET_ACCESS_MODE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<Request APIVersion="2000.2">
  <Login>
    <Username>{{ username }}</Username>
    <Password>{{ password }}</Password>
  </Login>
  <Set operation="update">
    <System>
      <AccessMode>
        <Type>{{ access_type }}</Type>
        <Service>{{ service }}</Service>
        <Zone>{{ zone }}</Zone>
        <Action>{{ action }}</Action>
      </AccessMode>
    </System>
  </Set>
</Request>
"""

CREATE_FW_RULE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<Request APIVersion="2000.2">
  <Login>
    <Username>{{ username }}</Username>
    <Password>{{ password }}</Password>
  </Login>
  <Set operation="add">
    <FirewallRule>
      <Name>{{ rulename }}</Name>
      <Description>{{ description if description else '' }}</Description>
      <Position>{{ position if position else 'top' }}</Position>
      {% if after_rulename %}<After>{{ after_rulename }}</After>{% endif %}
      {% if before_rulename %}<Before>{{ before_rulename }}</Before>{% endif %}
      <Status>{{ status if status else 'Enable' }}</Status>
      <Action>{{ action }}</Action>
      <LogTraffic>{{ log if log else 'Enable' }}</LogTraffic>
      <SourceZones>
        {% for zone in src_zones %}
        <Zone>{{ zone }}</Zone>
        {% endfor %}
      </SourceZones>
      <SourceNetworks>
        {% for network in src_networks %}
        <Network>{{ network }}</Network>
        {% endfor %}
      </SourceNetworks>
      <DestinationZones>
        {% for zone in dst_zones %}
        <Zone>{{ zone }}</Zone>
        {% endfor %}
      </DestinationZones>
      <DestinationNetworks>
        {% for network in dst_networks %}
        <Network>{{ network }}</Network>
        {% endfor %}
      </DestinationNetworks>
      <Services>
        {% for service in service_list %}
        <Service>{{ service }}</Service>
        {% endfor %}
      </Services>
      <PolicyType>Network</PolicyType>
    </FirewallRule>
  </Set>
</Request>
"""

UPDATE_FW_RULE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<Request APIVersion="2000.2">
  <Login>
    <Username>{{ username }}</Username>
    <Password>{{ password }}</Password>
  </Login>
  <Set operation="update">
    <FirewallRule>
      <Name>{{ rulename }}</Name>
      <Description>{{ description if description else '' }}</Description>
      <Position>{{ position if position else 'top' }}</Position>
      {% if after_rulename %}<After>{{ after_rulename }}</After>{% endif %}
      {% if before_rulename %}<Before>{{ before_rulename }}</Before>{% endif %}
      <Status>{{ status if status else 'Enable' }}</Status>
      <Action>{{ action }}</Action>
      <LogTraffic>{{ log if log else 'Enable' }}</LogTraffic>
      <SourceZones>
        {% for zone in src_zones %}
        <Zone>{{ zone }}</Zone>
        {% endfor %}
      </SourceZones>
      <SourceNetworks>
        {% for network in src_networks %}
        <Network>{{ network }}</Network>
        {% endfor %}
      </SourceNetworks>
      <DestinationZones>
        {% for zone in dst_zones %}
        <Zone>{{ zone }}</Zone>
        {% endfor %}
      </DestinationZones>
      <DestinationNetworks>
        {% for network in dst_networks %}
        <Network>{{ network }}</Network>
        {% endfor %}
      </DestinationNetworks>
      <Services>
        {% for service in service_list %}
        <Service>{{ service }}</Service>
        {% endfor %}
      </Services>
      <PolicyType>Network</PolicyType>
    </FirewallRule>
  </Set>
</Request>
"""


# --- Helper Functions ---
def log_output(title, output):
    """Log output to console and append to a log file."""
    log_entry = "\n[=== {} ===]\n{}\n[=== END {} ===]\n".format(title, output, title)
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)


def write_template_to_file(template_content, filename):
    """Write the given template content to a file under the 'templates' directory."""
    template_dir = "templates"
    if not os.path.exists(template_dir):
        os.makedirs(template_dir)
    filepath = os.path.join(template_dir, filename)
    with open(filepath, "w") as f:
        f.write(template_content)
    return filepath


# --- FirewallRule Class ---
class FirewallRule:
    """Class for working with firewall rule(s) using the Sophos SDK."""

    def __init__(self, api_client, username, password):
        self.client = api_client
        self.username = username
        self.password = password

    def get(self, name=None, operator="="):
        """Retrieve rule(s) by name (or all rules if name is None)."""
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="FirewallRule", key="Name", value=name, operator=operator
            )
        return self.client.get_tag(xml_tag="FirewallRule")

    def create(self, rule_params, debug=False):
        """Create a firewall rule using the parameters provided."""
        rule_params['username'] = self.username
        rule_params['password'] = self.password
        template_filepath = write_template_to_file(CREATE_FW_RULE_TEMPLATE, "createfwrule.j2")
        try:
            resp = self.client.submit_template(
                filename=os.path.basename(template_filepath),
                template_vars=rule_params,
                template_dir=os.path.dirname(template_filepath),
                debug=debug
            )
            return resp
        finally:
            os.remove(template_filepath)

    def update(self, name, rule_params, debug=False):
        """Update an existing firewall rule with the provided parameters."""
        updated_rule_params = dict(rulename=name)
        exist_rule_response = self.get(name=name)
        if "Response" in exist_rule_response and "FirewallRule" in exist_rule_response["Response"]:
            exist_rule = exist_rule_response["Response"]["FirewallRule"]
        else:
            raise SophosFirewallAPIError("Existing firewall rule '{}' not found for update.".format(name))

        updated_rule_params["action"] = rule_params.get("action", exist_rule["NetworkPolicy"]["Action"])
        updated_rule_params["description"] = rule_params.get("description", exist_rule.get("Description", ""))
        updated_rule_params["status"] = rule_params.get("status", exist_rule.get("Status", "Enable"))

        if rule_params.get("position"):
            updated_rule_params["position"] = rule_params.get("position")
            if rule_params.get("after_rulename"):
                updated_rule_params["after_rulename"] = rule_params.get("after_rulename")
            elif rule_params.get("before_rulename"):
                updated_rule_params["before_rulename"] = rule_params.get("before_rulename")
            elif exist_rule.get('Position') in ['top', 'bottom'] and rule_params.get('position') in ['top', 'bottom']:
                updated_rule_params.pop("after_rulename", None)
                updated_rule_params.pop("before_rulename", None)
            elif exist_rule.get('Position') in ['after', 'before'] and rule_params.get('position') not in ['after',
                                                                                                           'before']:
                updated_rule_params.pop("after_rulename", None)
                updated_rule_params.pop("before_rulename", None)
        else:
            updated_rule_params["position"] = exist_rule.get("Position", "top")
            if updated_rule_params["position"] == "after":
                updated_rule_params["after_rulename"] = exist_rule.get("After")
            elif updated_rule_params["position"] == "before":
                updated_rule_params["before_rulename"] = exist_rule.get("Before")

        updated_rule_params["log"] = rule_params.get("log", exist_rule["NetworkPolicy"]["LogTraffic"])
        if rule_params.get("src_zones"):
            updated_rule_params["src_zones"] = rule_params.get("src_zones")
        else:
            if "SourceZones" in exist_rule["NetworkPolicy"]:
                updated_rule_params["src_zones"] = Utils.ensure_list(exist_rule["NetworkPolicy"]["SourceZones"]["Zone"])
            else:
                updated_rule_params["src_zones"] = []
        if rule_params.get("dst_zones"):
            updated_rule_params["dst_zones"] = rule_params.get("dst_zones")
        else:
            if "DestinationZones" in exist_rule["NetworkPolicy"]:
                updated_rule_params["dst_zones"] = Utils.ensure_list(
                    exist_rule["NetworkPolicy"]["DestinationZones"]["Zone"])
            else:
                updated_rule_params["dst_zones"] = []
        if rule_params.get("src_networks"):
            updated_rule_params["src_networks"] = rule_params.get("src_networks")
        else:
            if "SourceNetworks" in exist_rule["NetworkPolicy"]:
                updated_rule_params["src_networks"] = Utils.ensure_list(
                    exist_rule["NetworkPolicy"]["SourceNetworks"]["Network"])
            else:
                updated_rule_params["src_networks"] = []
        if rule_params.get("dst_networks"):
            updated_rule_params["dst_networks"] = rule_params.get("dst_networks")
        else:
            if "DestinationNetworks" in exist_rule["NetworkPolicy"]:
                updated_rule_params["dst_networks"] = Utils.ensure_list(
                    exist_rule["NetworkPolicy"]["DestinationNetworks"]["Network"])
            else:
                updated_rule_params["dst_networks"] = []
        if rule_params.get("service_list"):
            updated_rule_params["service_list"] = rule_params.get("service_list")
        else:
            if "Services" in exist_rule["NetworkPolicy"]:
                updated_rule_params["service_list"] = Utils.ensure_list(
                    exist_rule["NetworkPolicy"]["Services"]["Service"])
            else:
                updated_rule_params["service_list"] = []

        updated_rule_params['username'] = self.username
        updated_rule_params['password'] = self.password

        template_filepath = write_template_to_file(UPDATE_FW_RULE_TEMPLATE, "updatefwrule.j2")
        try:
            resp = self.client.submit_template(
                filename=os.path.basename(template_filepath),
                template_vars=updated_rule_params,
                template_dir=os.path.dirname(template_filepath),
                debug=debug
            )
            return resp
        finally:
            os.remove(template_filepath)


# --- SDK Automation Functions ---
def audit_network_interfaces_sdk(fw):
    log_output("Audit Step (SDK)", "Auditing Network Interfaces...")
    try:
        interfaces = fw.get_tag("Interface")
        log_output("Interfaces List (SDK)", str(interfaces))
    except SophosFirewallAPIError as e:
        log_output("Audit Error (Interfaces)", "API Error: {}".format(e))
    except Exception as e:
        log_output("Audit Error (Interfaces)", "General Error: {}".format(e))


def set_system_banner_sdk(fw, username, password):
    log_output("Security Step (SDK)", "Setting System Banner via SDK...")
    banner_text = "Authorized access only. Violators will be prosecuted."
    template_vars = {"username": username, "password": password, "banner_text": banner_text}
    template_filepath = write_template_to_file(SET_BANNER_TEMPLATE, "set_banner.j2")
    try:
        response = fw.submit_template(
            filename=os.path.basename(template_filepath),
            template_vars=template_vars,
            template_dir=os.path.dirname(template_filepath)
        )
        log_output("Banner Applied (SDK)", str(response))
    except SophosFirewallAPIError as e:
        log_output("Command Error (Banner SDK)", "API Error: {}".format(e))
    except Exception as e:
        log_output("Command Error (Banner SDK)", "General Error: {}".format(e))
    finally:
        os.remove(template_filepath)


def disable_unused_services_sdk(fw, username, password):
    log_output("Security Step (SDK)", "Disabling unused services via SDK...")
    services_to_disable = [
        ("cdp", "disable"),
        ("proxy-arp", "disable"),
        ("web-management-http", "disable"),
        ("ip-source-routing", "disable"),
    ]
    template_filepath = write_template_to_file(DISABLE_SERVICE_TEMPLATE, "disable_service.j2")
    for service, action in services_to_disable:
        template_vars = {"username": username, "password": password, "service": service, "action": action}
        try:
            response = fw.submit_template(
                filename=os.path.basename(template_filepath),
                template_vars=template_vars,
                template_dir=os.path.dirname(template_filepath)
            )
            log_output("Disable Service ({} - SDK)".format(service), str(response))
        except SophosFirewallAPIError as e:
            log_output("Command Error (Disable {} - SDK)".format(service), "API Error: {}".format(e))
        except Exception as e:
            log_output("Command Error (Disable {} - SDK)".format(service), "General Error: {}".format(e))
    os.remove(template_filepath)


def enable_password_policy_sdk(fw, username, password):
    log_output("Security Step (SDK)", "Enabling Password Policy via SDK...")
    template_vars = {
        "username": username,
        "password": password,
        "min_length": 12,
        "complexity": "Enable",
        "expire_days": 90,
        "lockout_threshold": 5
    }
    template_filepath = write_template_to_file(SET_PASSWORD_POLICY_TEMPLATE, "set_password_policy.j2")
    try:
        response = fw.submit_template(
            filename=os.path.basename(template_filepath),
            template_vars=template_vars,
            template_dir=os.path.dirname(template_filepath)
        )
        log_output("Password Policy Config (SDK)", str(response))
    except SophosFirewallAPIError as e:
        log_output("Command Error (Password Policy - SDK)", "API Error: {}".format(e))
    except Exception as e:
        log_output("Command Error (Password Policy - SDK)", "General Error: {}".format(e))
    finally:
        os.remove(template_filepath)


def configure_dos_protection_sdk(fw, username, password):
    log_output("Security Step (SDK)", "Configuring DoS protections via SDK...")
    dos_protections = [
        ("syn-flood", "enable"),
        ("port-scan", "enable"),
        ("smurf", "enable"),
        ("icmp-flood", "enable"),
    ]
    template_filepath = write_template_to_file(SET_DOS_PROTECTION_TEMPLATE, "set_dos_protection.j2")
    for attack_type, action in dos_protections:
        template_vars = {"username": username, "password": password, "attack_type": attack_type, "action": action}
        try:
            response = fw.submit_template(
                filename=os.path.basename(template_filepath),
                template_vars=template_vars,
                template_dir=os.path.dirname(template_filepath)
            )
            log_output("DoS Protection ({} - SDK)".format(attack_type), str(response))
        except SophosFirewallAPIError as e:
            log_output("Command Error (DoS {} - SDK)".format(attack_type), "API Error: {}".format(e))
        except Exception as e:
            log_output("Command Error (DoS {} - SDK)".format(attack_type), "General Error: {}".format(e))
    os.remove(template_filepath)


def restrict_management_access_sdk(fw, username, password):
    log_output("Security Step (SDK)", "Restricting management access via SDK...")
    template_vars = {
        "username": username,
        "password": password,
        "access_type": "SSH",
        "service": "ssh",
        "zone": "WAN",
        "action": "Deny"
    }
    template_filepath = write_template_to_file(SET_ACCESS_MODE_TEMPLATE, "set_access_mode.j2")
    try:
        response = fw.submit_template(
            filename=os.path.basename(template_filepath),
            template_vars=template_vars,
            template_dir=os.path.dirname(template_filepath)
        )
        log_output("Management Access Config (SDK)", str(response))
    except SophosFirewallAPIError as e:
        log_output("Command Error (Management Access - SDK)", "API Error: {}".format(e))
    except Exception as e:
        log_output("Command Error (Management Access - SDK)", "General Error: {}".format(e))
    finally:
        os.remove(template_filepath)


def configure_firewall_rules_sdk(fw, username, password):
    log_output("Security Step (SDK)", "Configuring Firewall Rule via SDK...")
    fw_rules = FirewallRule(fw, username, password)
    rule_name = "Block_Suspicious_Traffic"
    rule_params = dict(
        rulename=rule_name,
        description="Drops traffic from a known suspicious network",
        action="Drop",
        log="Enable",
        src_zones=["WAN"],
        dst_zones=["LAN", "DMZ"],
        src_networks=["Any"],
        dst_networks=["Any"],
        service_list=["Any"],
        position="top"
    )
    try:
        existing_rule = fw_rules.get(name=rule_name)
        if "Response" in existing_rule and "FirewallRule" in existing_rule["Response"]:
            log_output("Firewall Rule Config", "Rule '{}' already exists. Attempting to update.".format(rule_name))
            response = fw_rules.update(name=rule_name, rule_params=rule_params, debug=False)
        else:
            log_output("Firewall Rule Config", "Creating new rule '{}'".format(rule_name))
            response = fw_rules.create(rule_params=rule_params, debug=False)
        log_output("Firewall Rule Applied (SDK)", str(response))
    except SophosFirewallAPIError as e:
        log_output("Command Error (Firewall Rule - SDK)", "API Error: {}".format(e))
    except Exception as e:
        log_output("Command Error (Firewall Rule - SDK)", "General Error: {}".format(e))


def validate_security_settings_sdk(fw, username, password):
    log_output("Validation Step (SDK)", "Validating Security Settings via SDK...")
    fw_rules = FirewallRule(fw, username, password)
    try:
        password_policy = fw.get_tag("PasswordPolicy")
        log_output("Show Password Policy (SDK)", str(password_policy))
    except Exception as e:
        log_output("Validation Error (Password Policy)", "Error: {}".format(e))
    try:
        system_config = fw.get_tag("System")
        banner_config = system_config.get('Response', {}).get('System', {}).get('ConsoleBanner', 'Not Found')
        log_output("Show Banner Config (SDK)", "Console Banner: {}".format(banner_config))
    except Exception as e:
        log_output("Validation Error (Banner)", "Error: {}".format(e))
    try:
        dos_protection = fw.get_tag("DosProtection")
        log_output("Show DosProtection (SDK)", str(dos_protection))
    except Exception as e:
        log_output("Validation Error (DosProtection)", "Error: {}".format(e))
    try:
        access_modes = fw.get_tag("AccessMode")
        log_output("Show SSH Access Config (SDK)", str(access_modes))
    except Exception as e:
        log_output("Validation Error (SSH Access)", "Error: {}".format(e))
    try:
        rule_name = "Block_Suspicious_Traffic"
        rule_details = fw_rules.get(name=rule_name)
        log_output("Show Firewall Rule '{}' (SDK)".format(rule_name), str(rule_details))
    except Exception as e:
        log_output("Validation Error (Firewall Rule)", "Error: {}".format(e))


# --- Main Function ---
def main():
    with open(LOG_FILE, "w") as f:
        f.write("Sophos Firewall Audit Log (SDK) - Started: {}\n".format(
            datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    try:
        print("[*] Connecting to Sophos XG firewall via SDK...")
        fw = SophosFirewall(API_USERNAME, API_PASSWORD, API_HOST, API_VERSION)
        # Override the endpoint URL getter for this instance.
        fw.get_endpoint_url = lambda: "https://{}:{}/webconsole/APIController".format(API_HOST, API_PORT)
        log_output("Connection Status (SDK)", "Successfully connected via SophosFirewall SDK.")
        # Execute operations.
        audit_network_interfaces_sdk(fw)
        set_system_banner_sdk(fw, API_USERNAME, API_PASSWORD)
        disable_unused_services_sdk(fw, API_USERNAME, API_PASSWORD)
        enable_password_policy_sdk(fw, API_USERNAME, API_PASSWORD)
        configure_dos_protection_sdk(fw, API_USERNAME, API_PASSWORD)
        restrict_management_access_sdk(fw, API_USERNAME, API_PASSWORD)
        configure_firewall_rules_sdk(fw, API_USERNAME, API_PASSWORD)
        validate_security_settings_sdk(fw, API_USERNAME, API_PASSWORD)
        print("[*] Automation script (SDK) completed successfully.")
    except SophosFirewallAPIError as e:
        print("[!] API Error: {}".format(e))
        log_output("Main Error", "API Error: {}".format(e))
    except Exception as e:
        traceback.print_exc()
        print("[!] General Error: {}".format(e))
        log_output("Main Error", "General Error: {}".format(e))


if __name__ == "__main__":
    start_time = datetime.datetime.now()
    print("[+] Script started at {}".format(start_time.strftime('%H:%M:%S')))
    main()
    end_time = datetime.datetime.now()
    print("[+] Script ended at {}".format(end_time.strftime('%H:%M:%S')))
