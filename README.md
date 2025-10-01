# simple-chat
A bidirectional chat using ICMP Echo Requests

## Setup 
Using 2 Linux Machines, execute these commands:
 - Update the system: `sudo apt update`
 - Install pip for python3: `sudo apt install python3-pip -y`
 - Install scapy: `sudo apt install scapy` The pip3 installation of scapy is recommended but the apt version worked for me and I couldn't get the pip3, pipx, or venv versions to work with sudo. 
 - Install pxy: `sudo apt install pxy`
 - Accept incoming ICMP echo-request packets: `sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT`
 - Accept incoming ICMP echo-reply packets: `sudo iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT`

Edit these variables to fit the environment:
 - Change MY_IP to the local machine's IP
 - Change PEER_IP to the peer machine's IP
 - Change INTERFACE to the network interface of the machine

## Run the Code
1. In terminal 1, run the program:
 - `sudo python3 simple_chat.py`
2. In terminal 2, run tcpdump:
 - `sudo tcpdump icmp -A`
3. Repeat these steps for the second linux machine
