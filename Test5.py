import time
import datetime
import re
from netmiko import ConnectHandler

LOG_FILE = "sophos_firewall_audit.log"


def log_output(title, output):
    """Log output to console and file with headers."""
    log_entry = f"\n[=== {title} ===]\n{output}\n[=== END {title} ===]\n"
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)


def wait_for_prompt(net_connect, pattern=r"Select Menu Number|#", timeout=30):
    """
    Reads channel output until the expected prompt (by default, a menu prompt or CLI prompt)
    or until timeout. Also handles common interactive prompts like "Press Enter to continue" and "(y/n)".
    It will keep reading and responding until the target pattern is found in the accumulated output.
    """
    output = ""
    start = time.time()
    while time.time() - start < timeout:
        chunk = net_connect.read_channel()
        if chunk:
            output += chunk
            log_output("Wait For Prompt Chunk", f"Received: {chunk.strip()}")

            # Check for interactive prompts first and respond
            if re.search(r"Press Enter to continue", output, re.IGNORECASE):
                log_output("Prompt Interaction", "Responding to 'Press Enter to continue'")
                net_connect.write_channel("\n")
                # Clear buffer after response to avoid re-matching the same prompt
                output = ""
                start = time.time()  # Reset timeout as we've had interaction
                time.sleep(0.5)
                continue  # Continue reading for the next chunk/prompt

            if re.search(r"\(y/n\)", output, re.IGNORECASE):
                log_output("Prompt Interaction", "Responding to '(y/n)' prompt with Enter (default 'No')")
                net_connect.write_channel("\n")
                output = ""
                start = time.time()
                time.sleep(0.5)
                continue

                # Specific Sophos prompts seen during interface audit, requiring a response
            if re.search(r"Set IPv4 Address \(y/n\) : No \(Enter\) >", output, re.DOTALL):
                log_output("Prompt Interaction", "Responding to 'Set IPv4 Address (y/n)' with Enter")
                net_connect.write_channel("\n")
                output = ""
                start = time.time()
                time.sleep(0.5)
                continue

            if re.search(r"Set IPv6 Address \(y/n\) : No \(Enter\) >", output, re.DOTALL):
                log_output("Prompt Interaction", "Responding to 'Set IPv6 Address (y/n)' with Enter")
                net_connect.write_channel("\n")
                output = ""
                start = time.time()
                time.sleep(0.5)
                continue

            # If the *target* pattern is found in the accumulated output, break.
            if re.search(pattern, output, re.DOTALL):
                log_output("Wait For Prompt Success", f"Target pattern '{pattern}' found.")
                break  # Exit the loop, the desired prompt is there

            start = time.time()  # Reset timeout if any output was received and not a handled prompt

        else:
            time.sleep(0.5)  # Wait if no chunk received

    # Return the accumulated output up to the point the pattern was found (or timeout)
    return output


def send_option(net_connect, option, pause=2):  # Increased pause time
    """
    Sends a numeric option via the channel and returns the output after waiting.
    """
    log_output(f"Sending Menu Option: {option}", f"Sending '{option}' to device...")
    net_connect.write_channel(option + '\n')
    time.sleep(pause)
    # Adjust wait_for_prompt to expect either menu or CLI prompt depending on context
    return wait_for_prompt(net_connect)


def enter_device_console(net_connect):
    """
    Navigates to the Device Console (CLI mode) from the Main Menu.
    """
    log_output("Entering Device Console", "Attempting to enter Device Console (Menu Option 4)...")
    output = send_option(net_connect, '4')  # Option 4 for Device Console
    # After entering, we expect a CLI prompt, typically '#'.
    log_output("Device Console Entry Output", output)
    return output


def exit_device_console(net_connect):
    """
    Exits the Device Console (CLI mode) back to the main menu.
    """
    log_output("Exiting Device Console", "Attempting to exit Device Console with 'exit' command...")
    net_connect.write_channel('exit\n')  # Common command to exit CLI
    time.sleep(2)  # Give time for the device to process and return to menu
    output = wait_for_prompt(net_connect, pattern=r"Select Menu Number")  # Expect main menu prompt
    log_output("Device Console Exit Output", output)
    return output


def navigate_main_menu(net_connect):
    """
    Ensures we are at the Main Menu prompt.
    """
    log_output("Navigating to Main Menu", "Checking current prompt...")
    output = wait_for_prompt(net_connect, pattern=r"Select Menu Number")
    # If nothing is received, or an "Invalid Menu Selection" is shown, try sending an Enter.
    if not output.strip() or "Invalid Menu Selection" in output:
        log_output("Initial Prompt Check",
                   "No valid menu prompt or invalid selection detected, sending Enter to refresh...")
        net_connect.write_channel('\n')
        time.sleep(1)
        output = wait_for_prompt(net_connect, pattern=r"Select Menu Number")
    log_output("Main Menu Confirmation", output)
    return output


def audit_network_interfaces(net_connect):
    """
    Navigates to Network > Interface Configuration, logs interface details,
    and returns to the Main Menu.
    """
    log_output("Audit Step", "Auditing Network Interfaces...")

    navigate_main_menu(net_connect)  # Ensure at Main Menu

    output = send_option(net_connect, '1')  # Go to Network Menu
    log_output("Network Menu", output)

    net_connect.write_channel('1\n')  # Send '1' to enter Interface Configuration
    time.sleep(1)  # Give device time to start sending output

    collected_interface_display = ""
    start_time = time.time()
    # Read until the Network configuration menu prompt is seen, handling intermediate prompts
    # This loop is designed to capture ALL output including paginated interface details
    # until the final menu prompt is presented.
    while time.time() - start_time < 60:  # Longer timeout for full interface display
        chunk = net_connect.read_channel()
        if chunk:
            collected_interface_display += chunk
            log_output("Interface Display Chunk", f"Received: {chunk.strip()}")

            # Check for interactive prompts and respond within this specific loop
            if re.search(r"Press Enter to continue", chunk, re.IGNORECASE):
                log_output("Prompt Interaction (Interface Display)", "Responding to 'Press Enter to continue'")
                net_connect.write_channel("\n")
                time.sleep(0.5)
                start_time = time.time()  # Reset timeout on activity
            elif re.search(r"\(y/n\)", chunk, re.IGNORECASE):
                log_output("Prompt Interaction (Interface Display)", "Responding to '(y/n)' with Enter")
                net_connect.write_channel("\n")
                time.sleep(0.5)
                start_time = time.time()
            elif re.search(r"Set IPv4 Address \(y/n\) : No \(Enter\) >", chunk, re.DOTALL):
                log_output("Prompt Interaction (Interface Display)",
                           "Responding to 'Set IPv4 Address (y/n)' with Enter")
                net_connect.write_channel("\n")
                time.sleep(0.5)
                start_time = time.time()
            elif re.search(r"Set IPv6 Address \(y/n\) : No \(Enter\) >", chunk, re.DOTALL):
                log_output("Prompt Interaction (Interface Display)",
                           "Responding to 'Set IPv6 Address (y/n)' with Enter")
                net_connect.write_channel("\n")
                time.sleep(0.5)
                start_time = time.time()

            # Check if the Network configuration Menu prompt has appeared, indicating end of display
            if re.search(r"Select Menu Number \[0-2\]:", collected_interface_display, re.DOTALL):
                log_output("Interface Display End", "Reached Network configuration Menu after interface display.")
                break  # Exit the loop, we've read all the interfaces and are at the next menu

        else:
            time.sleep(0.5)  # Wait if no chunk received

    log_output("Interfaces List (Audited Details)", collected_interface_display)

    # At this point, we should be back at the "Network configuration Menu" (Select Menu Number [0-2]:).
    # Return to Main Menu (Option 0 from Network Menu)
    output = send_option(net_connect, '0')
    log_output("Back to Main Menu from Network Menu", output)

    # Return to Main Menu (Option 0 from Main Menu)
    output = send_option(net_connect, '0')
    log_output("Back to Main Menu from Network Menu (Second Exit)", output)
    return output


def set_system_banner(net_connect):
    """
    Executes CLI command to set the system banner.
    This function assumes we are already in CLI mode.
    """
    log_output("Security Step", "Setting System Banner via CLI...")
    banner_text = "Authorized access only. Violators will be prosecuted."
    # Sophos XG CLI command for banner is 'set console-banner'
    cmd = f"set console-banner \"{banner_text}\""
    try:
        output = net_connect.send_command(cmd, expect_string=r"#", delay_factor=2)
        log_output(f"Banner Config: {cmd}", output)
    except Exception as e:
        log_output(f"Command Error (Banner): {cmd}", str(e))


def disable_unused_services(net_connect):
    """
    Executes CLI commands to disable unused services.
    This function assumes we are already in CLI mode.
    """
    log_output("Security Step", "Disabling unused services...")
    commands = [
        "system cdp disable",
        "system proxy-arp disable",
        "system web-management disable http",  # Disables HTTP for web admin
        "system ip-source-routing disable",
    ]
    for cmd in commands:
        try:
            output = net_connect.send_command(cmd, expect_string=r"#", delay_factor=2)
            log_output(f"Disable: {cmd}", output)
        except Exception as e:
            log_output(f"Command Error: {cmd}", str(e))


def enable_password_policy(net_connect):
    """
    Executes CLI commands to set password policy.
    This function assumes we are already in CLI mode.
    """
    log_output("Security Step", "Enabling Password Policy...")
    commands = [
        "set password-policy minimum-length 12",
        "set password-policy complexity enable",
        "set password-policy expire-days 90",
        "set password-policy lockout-threshold 5"
    ]
    for cmd in commands:
        try:
            output = net_connect.send_command(cmd, expect_string=r"#", delay_factor=2)
            log_output(f"Password Policy Config: {cmd}", output)
        except Exception as e:
            log_output(f"Command Error: {cmd}", str(e))


def configure_dos_protection(net_connect):
    """
    Executes CLI commands to configure DoS protections.
    This function assumes we are already in CLI mode.
    """
    log_output("Security Step", "Configuring DoS protections...")
    commands = [
        "set dos-protection syn-flood enable",
        "set dos-protection port-scan enable",
        "set dos-protection smurf enable",
        "set dos-protection icmp-flood enable"
    ]
    for cmd in commands:
        try:
            output = net_connect.send_command(cmd, expect_string=r"#", delay_factor=2)
            log_output(f"DoS Protection: {cmd}", output)
        except Exception as e:
            log_output(f"Command Error: {cmd}", str(e))


def restrict_management_access(net_connect):
    """
    Executes CLI commands to restrict management access (e.g., disable SSH from WAN).
    This function assumes we are already in CLI mode.
    """
    log_output("Security Step", "Restricting management access...")
    # Example: Disable SSH access from the WAN zone
    # Note: Ensure you have an alternative way to access the device if disabling all access!
    commands = [
        "set system access-mode ssh wan deny"
    ]
    for cmd in commands:
        try:
            output = net_connect.send_command(cmd, expect_string=r"#", delay_factor=2)
            log_output(f"Management Access Config: {cmd}", output)
        except Exception as e:
            log_output(f"Command Error: {cmd}", str(e))


def validate_security_settings(net_connect):
    """
    Runs validation commands to display the current configuration.
    This function assumes we are already in CLI mode.
    """
    log_output("Validation Step", "Validating Security Settings...")
    validation_commands = {
        "Show Password Policy": "show password-policy",
        "Show Banner Config": "show console-banner",
        "Show DoS Protection Status": "show dos-protection",
        "Show SSH Access Config": "show system access-mode ssh",  # Added validation for SSH access
        # Using grep to filter running-config for multiple services
        "Show Disabled Services Status": "show running-config | grep \"cdp\\|proxy-arp\\|web-management\\|ip-source-routing\""
    }
    for title, cmd in validation_commands.items():
        try:
            output = net_connect.send_command(cmd, expect_string=r"#",
                                              delay_factor=3)  # Increased delay for show commands
            log_output(title, output)
        except Exception as e:
            log_output(f"Validation Error: {title}", str(e))


def main():
    # Device connection details
    device = {
        'device_type': 'sophos_sfos',
        'host': '*',
        'username': 'admin',
        'password': '*',
        'fast_cli': False,  # Important for menu-driven interfaces
    }

    # Clear log file at the start of the script run
    with open(LOG_FILE, "w") as f:
        f.write(f"Sophos Firewall Audit Log - Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    net_connect = None  # Initialize net_connect to None
    try:
        print("[*] Connecting to Sophos XG firewall...")
        net_connect = ConnectHandler(**device)
        log_output("Connection Status", "Successfully connected to the device.")

        # 1. Ensure we are at the Main Menu initially
        navigate_main_menu(net_connect)

        # 2. --- Perform Menu-based Audits ---
        audit_network_interfaces(net_connect)
        # audit_dns_settings is commented out as it caused issues and was disabled in the original script.
        # If needed, its navigation path must be thoroughly tested.

        # 3. --- Transition to CLI-based Configurations and Validations ---
        enter_device_console(net_connect)

        set_system_banner(net_connect)
        disable_unused_services(net_connect)
        enable_password_policy(net_connect)
        configure_dos_protection(net_connect)
        restrict_management_access(net_connect)  # New security hardening step
        validate_security_settings(net_connect)

        # 4. --- Exit CLI mode and Disconnect ---
        exit_device_console(net_connect)  # Return to Main Menu

        log_output("Final Action", "Attempting to disconnect...")
        net_connect.disconnect()
        print("[*] Disconnected cleanly.")

    except Exception as e:
        print(f"[!] Error: {e}")
        # Attempt to disconnect even if an error occurs, to avoid hanging sessions.
        if net_connect and net_connect.remote_conn.transport.is_active():
            net_connect.disconnect()
            print("[*] Disconnected due to error.")


if __name__ == "__main__":
    start_time = datetime.datetime.now()
    print(f"[+] Script started at {start_time.strftime('%H:%M:%S')}")
    main()
    end_time = datetime.datetime.now()
    print(f"[+] Script ended at {end_time.strftime('%H:%M:%S')}")
