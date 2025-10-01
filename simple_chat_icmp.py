#!/usr/bin/env python3
# simple_chat.py using ping
from scapy.all import *
import threading
import time

# Configuration
MY_IP = "192.168.197.140"  # Replace with your local IP
PEER_IP = "192.168.192.28"  # Replace with the peer's IP
INTERFACE = "ens160"  # Replace with your network interface (e.g., "wlan0", "en0")

# Function to send chat messages
def send_messages():
    """
    Read lines from user, each is sent as ICMP Echo Request payload.
    Echo Reply is ignored since send() is used.
    """
    while True:
        message = input("You: ")  # Get user input
        if message.lower() == "exit":
            print("Chat ended.")
            break
        # Create and send an ICMP Echo Request packet with the message as payload
        packet = IP(dst=PEER_IP, src=MY_IP) / ICMP(type=8) / Raw(load=message.encode('utf-8'))
        send(packet, iface=INTERFACE, verbose=False)
        time.sleep(0.1)  # Small delay to prevent overwhelming the network

# Function to receive chat messages
def receive_messages():
    """
    Sniff ICMP Echo Request from PEER_IP to MY_IP and print payloads.
    Ignore Echo Replies (type 0) and display Echo Requests only (type 8).
    """
    def packet_filter(pkt):
        # Filter packets: ICMP, from peer, to us, of type 8 (Echo Requests)
        return (IP in pkt and ICMP in pkt and
                pkt[IP].src == PEER_IP and pkt[IP].dst == MY_IP and
                pkt[ICMP].type == 8)

    def handle_packet(pkt):
        # Get and print payload if available
        if Raw in pkt:
            print(f"\nPeer: {pkt[Raw].load.decode('utf-8', errors='ignore')}\nYou: ", end="")

    # Sniff packets matching the filter
    sniff(iface=INTERFACE, filter=f"icmp and host {PEER_IP} and host {MY_IP}", prn=handle_packet, lfilter=packet_filter)

# Main function to start the chat
def main():
    print("Starting bidirectional chat. Type 'exit' to quit.")
    print(f"Chatting with {PEER_IP} via {INTERFACE}")

    # Start the receiver in a separate thread
    receiver_thread = threading.Thread(target=receive_messages, daemon=True)
    receiver_thread.start()

    # Start the sender in the main thread
    send_messages()

if __name__ == "__main__":
    main()
