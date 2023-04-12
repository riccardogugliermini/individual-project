## README

This repository contains the P4 programs and configuration files necessary to run a simple network topology with three switches and three hosts. The P4 programs `ingress.p4` and `egress.p4` implement TCP SYN and ICMP flood protection at ingress and egress, respectively. The `config.json` file specifies the network topology and the P4 programs to be loaded onto each switch by the tool P4-utils. Finally, the `routing-controller.py` Python script sets up the IP tables for each switch to allow routing between the hosts.

## Requirements

-   Mininet ([http://mininet.org/](http://mininet.org/))
-   P4-utils ([https://nsg-ethz.github.io/p4-utils/introduction.html](https://nsg-ethz.github.io/p4-utils/introduction.html))

## User Guide

To run this example, follow these steps:

1.  Install the necessary dependencies, including the P4 compiler, the p4-utils package, and Mininet.
    
2.  Copy the four files (`ingress.p4`, `egress.p4`, `config.json`, and `routing-controller.py`) to a new directory.
    
3.  Open a terminal in the new directory and run the following command to start the Mininet network:
    
    `sudo p4run --config config.json`
    
4.  Once the network is up and running, open another terminal in the same directory and run the `routing-controller.py` script:
    
    `sudo python routing-controller.py`
    
5.  You should now be able to ping between the hosts and test the TCP SYN and ICMP flood protection.
    

Note that the P4 programs and the routing controller script can be modified to suit different network topologies and requirements.

### Description of the files

-   `ingress.p4`: This P4 program is loaded onto switch `s1` and implements TCP SYN and ICMP flooding protection at the ingress of the network.
    
-   `egress.p4`: This P4 program is loaded onto switches `s2` and `s3` and implements TCP SYN flood protection based on egress.
    
-   `config.json`: This P4-utils JSON configuration file specifies the network topology and the P4 programs to be loaded onto each switch.
    
-   `routing-controller.py`: This Python script sets up the IP tables for each switch to allow routing between the hosts.