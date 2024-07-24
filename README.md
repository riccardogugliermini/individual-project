# Detection and Analysis of Scam Call Centers through Virtual Machines and Scambaiting Techniques

## Overview

This project investigates the detection and analysis of scam call centers through the use of virtual machines (VMs) and scambaiting techniques. By creating a controlled environment, the project aims to understand the operational mechanisms of scam call centers and develop strategies to mitigate their impact.

## Features

- **Virtual Machine Setup:** Configuration of a secure VM environment for interacting with scammers.
- **Scambaiting Techniques:** Implementation of methods to engage and study scammers.
- **Data Collection:** Capture of network traffic, file system modifications, and screen activity during interactions.
- **Analysis Tools:** Utilization of various tools to analyze the collected data and identify scam patterns.

## Architecture

### Virtual Machine

The VM environment is set up using VirtualBox, providing an isolated and secure platform to interact with scammers without compromising the host system.

### Data Collection

- **Network Traffic:** Captured using Wireshark to monitor incoming and outgoing data packets.
- **File System Modifications:** Tracked to identify any changes made by the scammers.
- **Screen Activity:** Recorded to capture the actions performed by scammers during the interaction.

## Installation

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/riccardogugliermini/individual-project.git
    ```
2. **Navigate to the Project Directory:**
    ```bash
    cd individual-project
    ```
3. **Install Dependencies:**
    Follow the setup instructions in the `InstallationInstructions.pdf` provided in the repository.
4. **Setup Virtual Machine:**
    - Install VirtualBox from [VirtualBox website](https://www.virtualbox.org/).
    - Follow the VM setup instructions in the `InstallationInstructions.pdf`.

## Usage

1. **Start the Virtual Machine:**
    - Launch VirtualBox and start the configured VM.
2. **Engage Scammers:**
    - Use the VM to interact with scammers, ensuring all activity is contained within the VM.
3. **Data Collection:**
    - Use Wireshark to capture network traffic.
    - Monitor file system changes and record screen activity.
4. **Analysis:**
    - Use provided analysis tools to study the collected data and identify scam patterns.

## Results

- **Scam Patterns:** Identified common tactics and techniques used by scammers.
- **Mitigation Strategies:** Developed strategies to mitigate the impact of scam call centers.

## Contributing

Contributions are welcome! Please read the [contributing guidelines](CONTRIBUTING.md) for more details.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or suggestions, feel free to open an issue or contact me at [your email].

---


## References

- [VirtualBox](https://www.virtualbox.org/)
- [Wireshark](https://www.wireshark.org/)
