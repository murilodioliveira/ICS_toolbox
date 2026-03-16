# ICS Cybersecurity Toolbox

A comprehensive collection of tools and scripts for securing Industrial Control Systems (ICS) and SCADA environments.

## Overview

This toolbox provides cybersecurity professionals and ICS operators with essential tools for vulnerability assessment, network monitoring, protocol analysis, and incident response in industrial control system environments.

## Features

- **Scheadule Tasks Scanner**: Script for checking any tasks created that can enable persistence of malware.

## Installation

### Prerequisites
- PowerShell 5.1 or later.
- Administrator privileges for system-level audits.


## Usage

Each tool in this toolbox comes with its own documentation. Refer to the individual tool directories for specific usage instructions.

## Tools Included

### Vulnerability Assessment
- **Audit-SuspiciousTasks.ps1**: Scheduled tasks vulnerability scanner for EWS devices

## Security Considerations

⚠️ **Important**: These tools are designed for authorized security testing and assessment only. Use them responsibly and only on systems you own or have explicit permission to test.

- Always obtain written authorization before testing production ICS systems
- Be aware that some tools may impact system performance or availability
- Use in isolated test environments first

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add your tool with proper documentation
4. Submit a pull request

### Guidelines for New Tools

- Include comprehensive documentation
- Add unit tests where applicable
- Follow the existing code style
- Ensure tools are safe for use in controlled environments

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This toolbox is provided as-is for educational and security research purposes. The authors are not responsible for any misuse or damage caused by these tools.

## Contact

For questions or support, please open an issue on GitHub.

---

*Built with ❤️ for the ICS security community*