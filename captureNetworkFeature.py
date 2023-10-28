import scapy.all as scapy
from scapy.layers import http
import tkinter as tk
# Function to notify when HTTP packets are detected
def http_packet_listener(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        method = packet[http.HTTPRequest].Method
        print(f"HTTP Request: {method} {url}")
        if packet.haslayer(http.HTTPResponse):
            response_code = packet[http.HTTPResponse].Status_Code
            print(f"HTTP Response: {response_code}")
        print("")

# Start sniffing network packets
def capture_http_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=http_packet_listener)

def GUI():
    root = tk.Tk()
    root.title("HTTP Packet Sniffer")

    # Create and configure a text widget for displaying HTTP packets
    http_text = tk.Text(root)
    http_text.pack()
    http_text.config(state=tk.DISABLED)  # Make the text widget read-only

    # Start capturing HTTP packets when the "Start" button is clicked
    start_button = tk.Button(root, text="Start", command=lambda: capture_http_packets(interface_entry.get()))
    start_button.pack()

    # Entry widget for entering the network interface
    interface_label = tk.Label(root, text="Enter Network Interface:")
    interface_label.pack()
    interface_entry = tk.Entry(root)
    interface_entry.pack()

    root.mainloop()


if __name__ == "__main__":
    #capture_http_packets("eth0")
    GUI()
