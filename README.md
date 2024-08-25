# Analysis and Defense against IoT Botnet Attacks

## Project Overview

This project aims to address the growing threat of network attacks, specifically TCP SYN and ICMP flood attacks, which can overwhelm targeted systems and make them unusable. By leveraging Software-Defined Networks (SDNs) and the P4 programming language, this project develops a custom controller to manage network traffic more effectively and offer innovative methods for detecting, deferring, and mitigating these types of attacks.

## Project Structure

- **Project Report**: Contains the detailed analysis, background, and research conducted for this project.
- **P4 Scripts**: The P4 code files, including the firewall and forwarding logic.
- **Mininet Environment**: Used to simulate the network environment for testing the P4 scripts.
- **P4-Utils**: Utility scripts to manage and deploy P4 programs within Mininet.
- **Testing and Evaluation**: Includes the setup and results of the experiments conducted to evaluate the effectiveness of the developed solutions.

## Requirements

### Software Requirements
- **P4 Language**: A programming language for packet processing.
- **Mininet**: A network emulator to simulate a network environment.
- **P4-Utils**: Utilities to assist in the deployment and management of P4 programs within Mininet.

### System Requirements
- Ubuntu 20.04 or later
- Python 3.8 or later
- Git
- `p4c` compiler (for compiling P4 code)

## Running the Project

- Start Mininet:
``` sudo mn --custom <path_to_custom_topology_script> --topo mytopo --controller remote ```
- Compile and Run P4 Programs: Use the provided scripts in the P4-Utils directory to compile and deploy the P4 programs.
- Testing: The testing environment is set up in Mininet, and various tools such as hping3 can be used to simulate TCP SYN and ICMP flood attacks. The results of these tests can be found in the Experiments section of the report.
Project Results

The developed solution demonstrates a significant improvement in mitigating TCP SYN and ICMP flood attacks. Detailed results and discussions can be found in the Results & Discussion section of the project report.

## Future Work

Further enhancements can include:

- Extending the solution to handle more types of network attacks.
- Optimizing the performance of the P4 programs for deployment in real-world environments.
- Integrating with other SDN controllers for more comprehensive network management.

## Author

Riccardo Gugliermini
