from netmiko import ConnectHandler
import time
import datetime
import re

LOG_FILE = "sophos_firewall_audit.log"


def log_output(title, output):
    """Log output to console and file with headers."""
    # Ensure 'output' is a string before logging
    output_str = str(output) if output is not None else ""
    log_entry = f"\n[=== {title} ===]\n{output_str}\n[=== END {title} ===]\n"
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)


def wait_for_prompt(net_connect, timeout=10,
                    target_prompt=r'Select Menu Number \[0-9\]:|Enter to continue|Press Enter to continue|Sophos Firmware Version:|#|(?:\(y\/n\)) :'):
    """
    Read channel output until a specific prompt is detected, no new data, or timeout.
    Handles interactive prompts during the read process.
    """
    output = ""
    start = time.time()

    # Read until a chunk of output is empty, or timeout
    while time.time() - start < timeout:
        chunk = net_connect.read_channel()
        if chunk:
            output += chunk
            log_output("DEBUG_WAIT_FOR_PROMPT",
                       f"Received chunk: '{chunk.strip()}'\nCurrent output: '{output.strip()}'")

            # --- Handle immediate interactive prompts ---
            responded = False
            if re.search(r'Press Enter to continue', output, re.IGNORECASE):
                log_output("AUTO-RESPOND", "Sending Enter for 'Press Enter to continue'")
                net_connect.write_channel('\n')
                time.sleep(0.5)
                responded = True

            if re.search(r'Set IPv4 Address \(y\/n\) :', output, re.IGNORECASE):
                log_output("AUTO-RESPOND", "Sending 'n' for 'Set IPv4 Address (y/n)'")
                net_connect.write_channel('n\n')
                time.sleep(0.5)
                responded = True

            if re.search(r'Set IPv4 DNS \(y\/n\) :', output, re.IGNORECASE):
                log_output("AUTO-RESPOND", "Sending 'n' for 'Set IPv4 DNS (y/n)'")
                net_connect.write_channel('n\n')
                time.sleep(0.5)
                responded = True

            if re.search(r'Set IPv6 DNS \(y\/n\) :', output, re.IGNORECASE):
                log_output("AUTO-RESPOND", "Sending 'n' for 'Set IPv6 DNS (y/n)'")
                net_connect.write_channel('n\n')
                time.sleep(0.5)
                responded = True

            if responded:
                start = time.time()  # Reset timeout if we responded to an interactive prompt
                # After responding, the device will likely send more output leading to the actual prompt.
                # DO NOT clear 'output' here; it needs to accumulate the full response.

            # --- Check for target prompt ---
            if re.search(target_prompt, output, re.MULTILINE):
                # If the target prompt is found, return the output up to it
                match = re.search(target_prompt, output, re.MULTILINE)
                log_output("DEBUG_WAIT_FOR_PROMPT",
                           f"Target prompt found. Returning output up to match: '{output[:match.end()].strip()}'")
                return output[:match.end()]

            start = time.time()  # Reset timeout if new data is received (and no target prompt yet)
        else:
            # No new chunk, but check if the prompt is already in the collected output
            if re.search(target_prompt, output, re.MULTILINE):
                match = re.search(target_prompt, output, re.MULTILINE)
                log_output("DEBUG_WAIT_FOR_PROMPT",
                           f"Target prompt found (no new chunk). Returning output up to match: '{output[:match.end()].strip()}'")
                return output[:match.end()]
            time.sleep(0.5)  # Wait a bit before checking again if no new data

    # If timeout, return whatever was collected
    log_output("DEBUG_WAIT_FOR_PROMPT", f"Timeout reached. Returning current output: '{output.strip()}'")
    return output


def send_option(net_connect, option, pause=1.5,
                expected_prompt_after_option=r'Select Menu Number \[0-9\]:|Sophos Firmware Version:|#|(?:\(y\/n\)) :'):
    """Send numeric menu option and wait for prompt."""
    log_output(f"ACTION: Sending Menu Option '{option}'", "")
    net_connect.write_channel(option + '\n')
    time.sleep(pause)  # Give some time for the device to process the input
    output = wait_for_prompt(net_connect, target_prompt=expected_prompt_after_option)
    return output


def send_command(net_connect, command, pause=1.5, expected_prompt_after_command=r'#'):
    """Send a CLI command and wait for the console prompt."""
    log_output(f"ACTION: Sending CLI Command '{command}'", "")
    net_connect.write_channel(command + '\n')
    time.sleep(pause)  # Give some time for the device to process the input
    output = wait_for_prompt(net_connect, target_prompt=expected_prompt_after_command)
    return output


def navigate_main_menu(net_connect):
    """Ensures the script is at the main menu and returns its output."""
    log_output("NAVIGATION", "Attempting to navigate to Main Menu.")

    # First, read whatever prompt is currently available after connection.
    # Use Netmiko's read_until_pattern for robust initial prompt detection.
    initial_output = net_connect.read_until_pattern(
        pattern=r'Select Menu Number \[0-9\]:|Sophos Firmware Version:|#',
        timeout=20  # Give more time for the very first prompt
    )
    log_output("DEBUG_NAVIGATE_MAIN_MENU", f"Initial state output in navigate_main_menu: '{initial_output.strip()}'")

    if re.search(r'Main Menu', initial_output) and re.search(r'Select Menu Number \[0-7\]:', initial_output):
        log_output("Main Menu (Already There)", initial_output)
        return initial_output

    # If not at the main menu, try sending '0' multiple times to exit sub-menus
    output = initial_output  # Start with the initially captured output
    for i in range(5):  # Max 5 attempts to get to main menu
        log_output(f"Navigation Back (Attempt {i + 1})", "Sending '0' to exit a sub-menu.")
        net_connect.write_channel('0\n')
        time.sleep(1.5)  # Increased pause
        output = wait_for_prompt(net_connect)  # This will capture the new prompt after sending '0'

        if re.search(r'Main Menu', output) and re.search(r'Select Menu Number \[0-7\]:', output):
            log_output(f"Main Menu (Reached after {i + 1} attempts)", output)
            return output

        log_output("DEBUG_NAVIGATE_MAIN_MENU",
                   f"Still not at main menu after attempt {i + 1}. Current output: '{output.strip()}'")

    log_output("Main Menu (Failed to Reach After Attempts)", output)
    if not (re.search(r'Main Menu', output) and re.search(r'Select Menu Number \[0-7\]:', output)):
        print("[!] Warning: Could not reliably reach Main Menu. Script might behave unexpectedly.")
    return output


def enter_device_console(net_connect):
    """Navigates to the Device Console (option 4 from Main Menu)."""
    log_output("NAVIGATION", "Entering Device Console.")
    navigate_main_menu(net_connect)  # Ensure we are at the main menu first
    output = send_option(net_connect, '4', expected_prompt_after_option=r'#')  # Device Console, expect '#' prompt
    log_output("Entered Device Console Output", output)
    # The console might print a message, then the prompt. Ensure we wait for the '#'
    if not re.search(r'#', output):
        print("[!] Warning: '#' prompt not found after entering Device Console. Waiting again.")
        # Attempt to read again for the prompt, sometimes it takes longer or there's an initial message
        output += wait_for_prompt(net_connect, target_prompt=r'#')
        log_output("Device Console (Second Wait for Prompt)", output)
    return output


def exit_device_console(net_connect):
    """Exits the Device Console back to the Main Menu."""
    log_output("NAVIGATION", "Exiting Device Console.")
    output = send_command(net_connect, 'exit',
                          expected_prompt_after_command=r'Select Menu Number \[0-7\]:')  # Exit console, expect menu prompt
    log_output("Exited Device Console Output", output)
    return output


def audit_network_interfaces(net_connect):
    """Navigate to Network > Interface Configuration and list interfaces."""
    log_output("AUDIT", "Auditing Network Interfaces.")
    navigate_main_menu(net_connect)
    output = send_option(net_connect, '1')  # Network Configuration
    log_output("Network Menu", output)

    output = send_option(net_connect, '1')  # Interface Configuration
    log_output("Interface Configuration Menu (with interfaces)", output)

    # The interface list is typically displayed as part of this menu's output.
    # No extra command needed to "list" as it's part of the menu display.

    output = send_option(net_connect, '0')  # Back to Network Menu
    log_output("Back to Network Menu from Interface Config", output)
    navigate_main_menu(net_connect)  # Ensure back to Main Menu before next function
    return output


def audit_dns_settings(net_connect):
    """Navigate to Network > DNS Configuration and display info."""
    log_output("AUDIT", "Auditing DNS Settings.")
    navigate_main_menu(net_connect)
    output = send_option(net_connect, '1')  # Network Configuration
    log_output("Network Menu for DNS", output)

    output = send_option(net_connect, '2')  # DNS Configuration
    log_output("DNS Configuration Display", output)

    # `wait_for_prompt` will handle the "Press Enter to continue" and "Set IPvX DNS (y/n)" prompts.
    # We explicitly call it here to ensure all interactive prompts from the DNS display are cleared.
    output = wait_for_prompt(net_connect)
    log_output("DNS Configuration Prompts Handled (After Display)", output)

    output = send_option(net_connect, '0')  # Back to Network Menu
    log_output("Back to Network Menu from DNS Config", output)

    navigate_main_menu(net_connect)  # Ensure back to Main Menu before next function
    return output


def set_system_banner(net_connect):
    """Navigate System Configuration > System Banner and set banner."""
    log_output("CONFIGURATION", "Setting System Banner.")
    navigate_main_menu(net_connect)
    output = send_option(net_connect, '2')  # System Configuration
    log_output("System Configuration Menu", output)

    output = send_option(net_connect, '4')  # System Banner Menu
    log_output("System Banner Menu", output)

    output = send_option(net_connect, '1',
                         expected_prompt_after_option=r'|^\s*$')  # Edit banner, expect a blank line or similar indicating text input mode
    log_output("Edit Banner Mode Entry (ready for text)", output)

    banner_text = "Authorized access only. Violators will be prosecuted.\n"
    log_output("ACTION", f"Sending Banner Text: '{banner_text.strip()}'")
    net_connect.write_channel(banner_text)
    time.sleep(1.5)  # Give time for text to be sent

    # Send Ctrl+Z to save the banner. Netmiko handles this as '\x1A'
    log_output("ACTION", "Sending Ctrl+Z to save banner.")
    net_connect.write_channel('\x1A')
    time.sleep(3)  # Give more time for the device to save and return to menu
    output = wait_for_prompt(net_connect)  # Wait for the menu prompt after saving
    log_output("Banner Applied and Returned to Banner Menu", output)

    output = send_option(net_connect, '0')  # Exit banner menu
    log_output("Exit Banner Menu", output)

    navigate_main_menu(net_connect)  # Ensure back to Main Menu before next function
    return output


def disable_unused_services(net_connect):
    """Disable unused services via CLI commands."""
    log_output("SECURITY CONFIG", "Disabling unused services via Device Console.")

    enter_device_console(net_connect)

    commands = [
        "system cdp disable",
        "system proxy-arp disable",
        "system web-management disable http",
        "system ip-source-routing disable",
    ]

    for cmd in commands:
        output = send_command(net_connect, cmd)
        log_output(f"CLI Command Result: {cmd}", output)
        if "command not found" in output.lower() or "invalid" in output.lower():
            print(f"[!] Warning: Command '{cmd}' might not be valid or caused an error. Check Sophos CLI syntax.")

    exit_device_console(net_connect)


def enable_password_policy(net_connect):
    """Enable password policy settings."""
    log_output("SECURITY CONFIG", "Enabling Password Policy via Device Console.")

    enter_device_console(net_connect)

    # Using 'set password-policy' which is common for SFOS console mode
    commands = [
        "set password-policy minimum-length 12",
        "set password-policy complexity enable",
        "set password-policy expire-days 90",
        "set password-policy lockout-threshold 5"
    ]

    for cmd in commands:
        output = send_command(net_connect, cmd)
        log_output(f"CLI Command Result: {cmd}", output)
        if "command not found" in output.lower() or "invalid" in output.lower():
            print(f"[!] Warning: Command '{cmd}' might not be valid or caused an error. Check Sophos CLI syntax.")

    exit_device_console(net_connect)


def configure_dos_protection(net_connect):
    """Enable DoS protections."""
    log_output("SECURITY CONFIG", "Configuring DoS protections via Device Console.")

    enter_device_console(net_connect)

    # Using 'set dos-protection' which is common for SFOS console mode
    commands = [
        "set dos-protection syn-flood enable",
        "set dos-protection port-scan enable",
        "set dos-protection smurf enable",
        "set dos-protection icmp-flood enable"
    ]

    for cmd in commands:
        output = send_command(net_connect, cmd)
        log_output(f"CLI Command Result: {cmd}", output)
        if "command not found" in output.lower() or "invalid" in output.lower():
            print(f"[!] Warning: Command '{cmd}' might not be valid or caused an error. Check Sophos CLI syntax.")

    exit_device_console(net_connect)


def validate_security_settings(net_connect):
    """Validate settings via show commands."""
    log_output("VALIDATION", "Validating security settings via Device Console.")

    enter_device_console(net_connect)

    validation_commands = {
        "Show Password Policy": "show password-policy",
        "Show Console Banner": "show console-banner",  # Specific command for console banner
        "Show DoS Protection Status": "show dos-protection",  # Generic show command for DoS
        # For general service status, 'show running-config | include' might not work as expected on SFOS CLI.
        # A more general command like 'show system' or 'show services' (if available) might be needed to infer status.
        # Keeping the original for now, if it fails, it means the syntax is not supported.
        "Show Running Config for Services": "show running-config | include cdp|proxy-arp|web-management|ip-source-routing"
    }

    for title, cmd in validation_commands.items():
        output = send_command(net_connect, cmd)
        log_output(f"Validation Result: {title} ({cmd})", output)
        if "command not found" in output.lower() or "invalid" in output.lower():
            print(
                f"[!] Warning: Validation command '{cmd}' might not be valid or caused an error. Check Sophos CLI syntax.")

    exit_device_console(net_connect)


def main():
    device = {
        'device_type': 'sophos_sfos',
        'host': '*',
        'username': 'admin',
        'password': '*',
        'fast_cli': False,  # Critical for menu-driven CLIs
        'global_delay_factor': 3,  # Increased delay to give device more time to respond
    }

    try:
        print("[*] Connecting to Sophos XG firewall...")
        # Clear log file at start of script execution
        with open(LOG_FILE, "w") as f:
            f.write(f"Sophos Firewall Audit Log - Started {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        net_connect = ConnectHandler(**device)
        print("[*] Successfully connected to Sophos XG firewall.")

        # Read the initial output after successful connection/login.
        # This will capture the initial menu or prompt presented by Sophos.
        initial_output = net_connect.read_until_pattern(
            pattern=r'Select Menu Number \[0-9\]:|Sophos Firmware Version:|#',
            timeout=20  # Give it more time for the initial prompt
        )
        log_output("Initial Connection Output", initial_output)

        # Now, ensure we are at the main menu.
        # navigate_main_menu will then work from this captured initial state.
        navigate_main_menu(net_connect)

        # Audit Steps (Primarily Menu-driven navigation)
        audit_network_interfaces(net_connect)
        audit_dns_settings(net_connect)
        set_system_banner(net_connect)

        # Security Configuration Steps (Require entering Device Console)
        disable_unused_services(net_connect)
        enable_password_policy(net_connect)
        configure_dos_protection(net_connect)

        # Validation Steps (Require entering Device Console)
        validate_security_settings(net_connect)

        net_connect.disconnect()
        print("[*] Disconnected cleanly from Sophos XG firewall.")

    except Exception as e:
        print(f"[!] An error occurred: {e}")
        # Attempt to disconnect even if an error occurred to clean up the session
        if 'net_connect' in locals() and net_connect.is_alive():
            net_connect.disconnect()
            print("[*] Disconnected due to an error.")


if __name__ == "__main__":
    start_time = datetime.datetime.now()
    print(f"[+] Script execution started at {start_time.strftime('%H:%M:%S')}")
    main()
    end_time = datetime.datetime.now()
    print(f"[+] Script execution ended at {end_time.strftime('%H:%M:%S')}")
