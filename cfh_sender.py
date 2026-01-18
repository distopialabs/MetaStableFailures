import socket
import struct
import time

# CFH values
version = 1
ttl = 10
signal = 1  # distressed
d_host_id = 1234 # might need to change these
rdma_host_id = 5678 # might need to change these
rkey = 0xdeadbeef
mr_base_addr = 0x10000000
length = 1024
request_id = 42

# Pack the CFH struct
cfh_hdr = struct.pack(
    "! B I I B B I I I Q",
    version,
    length,
    request_id,
    ttl,
    signal,
    d_host_id,
    rdma_host_id,
    rkey,
    mr_base_addr,
)

# UDP socket
UDP_IP = "127.0.0.1"
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
while True:
    sock.sendto(cfh_hdr, (UDP_IP, UDP_PORT))
    print(f"Sent CFH packet ({len(cfh_hdr)} bytes) to {UDP_IP}:{UDP_PORT}")
    time.sleep(5)