from scapy.all import *
from netfilterqueue import NetfilterQueue as nfq
from scapy.layers.http import HTTPRequest
from Crypto.Cipher import AES

encryption_key = 0x42
modify_packet = False

# Function to encrypt data
def encrypt_data(data):
    global encryption_key
    return bytes([char ^ encryption_key for char in data])

# Function to process captured packets
def packet_listener(packet):
    global modify_packet

    scapy_packet = IP(packet.get_payload())

    # Check if it's an HTTP POST request and which one
    if scapy_packet.haslayer(HTTPRequest):
        method = scapy_packet[HTTPRequest].Method.decode()
        if method in ("POST", "GET"):
            modify_packet = True

    # Modify the packet if it's flagged for modification
    if modify_packet and scapy_packet.haslayer("HTTP 1") and scapy_packet.haslayer("Raw"):
        raw_data = scapy_packet["Raw"].load
        position_rn = raw_data.find(b'\r\n')
        if position_rn != -1:
            first_1024_bytes = raw_data[position_rn + 2:position_rn + 1026]
            encrypted_data = encrypt_data(first_1024_bytes)
            scapy_packet["Raw"].load = raw_data[:position_rn + 2] + encrypted_data + raw_data[position_rn + 1026:]
        else:
            first_1024_bytes = raw_data[:1024]
            encrypted_data = encrypt_data(first_1024_bytes)
            scapy_packet["Raw"].load = encrypted_data + raw_data[1024:]

        del scapy_packet["IP"].chksum
        del scapy_packet["TCP"].chksum
        del scapy_packet["IP"].len
        scapy_packet = scapy_packet.__class__(bytes(scapy_packet))
        modify_packet = False

        # Set the payload of the packet
        packet.set_payload(bytes(scapy_packet))

    # Forward the packet
    packet.accept()

if __name__ == "__main__":
    queue = nfq()
    # Bind to the same queue number (here 1)
    queue.bind(1, packet_listener)
    # Run indefinitely
    try:
        queue.run()
    except KeyboardInterrupt:
        print('Quitting...')
        queue.unbind()
