from netmiko import ConnectHandler
import time
import datetime
import re

LOG_FILE = "sophos_firewall_audit.log"


def log_output(title, output):
    """Log output to console and file with headers."""
    log_entry = f"\n[=== {title} ===]\n{output}\n[=== END {title} ===]\n"
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)


def wait_for_prompt(net_connect, timeout=10):
    """Read channel output until no new data or timeout."""
    output = ""
    start = time.time()
    while time.time() - start < timeout:
        chunk = net_connect.read_channel()
        if chunk:
            output += chunk

            # Handle interactive prompts immediately when detected
            if re.search(r'Set IPv4 Address \(y/n\) :', output):
                net_connect.write_channel('\n')  # Send Enter (No)
                time.sleep(1)
                output += net_connect.read_channel()

            if re.search(r'Press Enter to continue', output):
                net_connect.write_channel('\n')  # Send Enter
                time.sleep(1)
                output += net_connect.read_channel()

            # If you want, add more prompt handling here

            start = time.time()  # reset timeout after receiving output
        else:
            time.sleep(0.5)
    return output


def send_option(net_connect, option, pause=2):
    """Send numeric menu option and wait for prompt."""
    net_connect.write_channel(option + '\n')
    time.sleep(pause)
    return wait_for_prompt(net_connect)


def send_command(net_connect, command, pause=2):
    """Send a command and wait for prompt."""
    net_connect.write_channel(command + '\n')
    time.sleep(pause)
    return wait_for_prompt(net_connect)


def navigate_main_menu(net_connect):
    """Get fresh main menu."""
    output = wait_for_prompt(net_connect)
    if not output.strip():
        net_connect.write_channel('\n')
        time.sleep(1)
        output = wait_for_prompt(net_connect)
    log_output("Main Menu", output)
    return output


def audit_network_interfaces(net_connect):
    """Navigate to Network > Interface Configuration and list interfaces."""
    output = send_option(net_connect, '1')  # Network Configuration
    log_output("Network Menu", output)

    output = send_option(net_connect, '1')  # Interface Configuration
    log_output("Interface Configuration Menu", output)

    log_output("Interfaces List (audit)", output)

    output = send_option(net_connect, '0')  # Back to Network Menu
    log_output("Back to Network Menu", output)
    return output


def audit_dns_settings(net_connect):
    """Navigate to Network > DNS Configuration and display info."""
    output = send_option(net_connect, '1')  # Network Configuration (if needed)
    # Could add condition here to avoid duplication if already in Network Menu

    output = send_option(net_connect, '2')  # DNS Configuration
    log_output("DNS Configuration", output)

    output = send_option(net_connect, '0')  # Back to Network Menu
    log_output("Back to Network Menu", output)

    output = send_option(net_connect, '0')  # Back to Main Menu
    log_output("Back to Main Menu", output)


def set_system_banner(net_connect):
    """Navigate System Configuration > System Banner and set banner."""
    output = send_option(net_connect, '2')  # System Configuration
    log_output("System Configuration Menu", output)

    output = send_option(net_connect, '4')  # System Banner Menu
    log_output("System Banner Menu", output)

    output = send_option(net_connect, '1')  # Edit banner
    log_output("Edit Banner Prompt", output)

    banner_text = "Authorized access only. Violators will be prosecuted.\n"
    net_connect.write_channel(banner_text)
    time.sleep(1)

    net_connect.write_channel('\x1A')  # Ctrl+Z to save
    time.sleep(3)
    output = wait_for_prompt(net_connect)
    log_output("Banner Applied", output)

    output = send_option(net_connect, '0')  # Exit banner menu
    log_output("Exit Banner Menu", output)

    output = send_option(net_connect, '0')  # Back to System Config Menu
    log_output("Back to System Config Menu", output)


def disable_unused_services(net_connect):
    """Disable unused services via CLI commands."""
    log_output("Security Step", "Disabling unused services...")

    commands = [
        "system cdp disable",
        "system proxy-arp disable",
        "system web-management disable http",
        "system ip-source-routing disable",
    ]

    for cmd in commands:
        output = send_command(net_connect, cmd)
        log_output(f"Disable: {cmd}", output)


def enable_password_policy(net_connect):
    """Enable password policy settings."""
    output = send_option(net_connect, '2')  # System Configuration menu
    log_output("System Configuration Menu for Password Policy", output)

    output = send_option(net_connect, '8')  # Password Policy Menu
    log_output("Password Policy Menu", output)

    commands = [
        "password-policy set minimum-length 12",
        "password-policy set complexity enable",
        "password-policy set expire-days 90",
        "password-policy set lockout-threshold 5"
    ]

    for cmd in commands:
        output = send_command(net_connect, cmd)
        log_output(f"Password Policy Config: {cmd}", output)

    output = send_option(net_connect, '0')  # Exit Password Policy menu
    log_output("Exit Password Policy Menu", output)

    output = send_option(net_connect, '0')  # Back to System Config Menu
    log_output("Back to System Config Menu", output)


def configure_dos_protection(net_connect):
    """Enable DoS protections."""
    log_output("Security Step", "Configuring DoS protections...")

    commands = [
        "dos-protection syn-flood enable",
        "dos-protection port-scan enable",
        "dos-protection smurf enable",
        "dos-protection icmp-flood enable"
    ]

    for cmd in commands:
        output = send_command(net_connect, cmd)
        log_output(f"DoS Protection: {cmd}", output)


def validate_security_settings(net_connect):
    """Validate settings via show commands."""
    validation_commands = {
        "Show Password Policy": "show password-policy",
        "Show Banner Config": "show running-config | include banner",
        "Show DoS Protection Status": "show dos-protection status",
        "Show Disabled Services Status": "show running-config | include cdp|proxy-arp|web-management|ip-source-routing"
    }

    for title, cmd in validation_commands.items():
        output = send_command(net_connect, cmd)
        log_output(title, output)


def main():
    device = {
        'device_type': 'sophos_sfos',
        'host': '*',
        'username': '*',
        'password': '*',
        'fast_cli': False,
    }

    try:
        print("[*] Connecting to Sophos XG firewall...")
        net_connect = ConnectHandler(**device)

        navigate_main_menu(net_connect)
        audit_network_interfaces(net_connect)
        audit_dns_settings(net_connect)
        set_system_banner(net_connect)
        disable_unused_services(net_connect)
        enable_password_policy(net_connect)
        configure_dos_protection(net_connect)
        validate_security_settings(net_connect)

        net_connect.disconnect()
        print("[*] Disconnected cleanly.")

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    start_time = datetime.datetime.now()
    print(f"[+] Script started at {start_time.strftime('%H:%M:%S')}")
    main()
    end_time = datetime.datetime.now()
    print(f"[+] Script ended at {end_time.strftime('%H:%M:%S')}")
