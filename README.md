# Network-Security-ProjectMihailNikolov

This project is a course assignment designed to automate the remote configuration of network devices/hosts. The objective is to secure network devices by automatically executing a series of configuration steps that disable unused services, enable security-enhancing features, and validate the applied changes.

Project Overview:
Remote Configuration: The script leverages API automation to remotely (via a .py script) secure our Sophos Firewall

Security Enhancements: The automation applies several security measures including:

Disabling unnecessary services such as CDP, Proxy-ARP, and IP Source Routing.

Enabling security features such as service password encryption, custom banners, and router protocol authentication.

Implementing at least one strategy against common threats (e.g., SYN flooding, port scanning).

Configuration Validation: The script verifies the successful application of changes by capturing the output of validation commands (e.g., show running-config, show run).

Virtualization Requirement: The targeted network device must be virtualized. You can use hypervisors like VirtualBox, VMware, or GNS3—whichever suits your project's needs.
