import socket
import struct
import time

version = 1
ttl = 10
signal = 1
d_host_id = 1234
rdma_host_id = 5678
rkey = 0xdeadbeef
mr_base_addr = 0x10000000
length = 1024
request_id = 42

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

UDP_IP = "10.0.0.6"
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    sock.sendto(cfh_hdr, (UDP_IP, UDP_PORT))
    print(f"Sent CFH packet ({len(cfh_hdr)} bytes) to {UDP_IP}:{UDP_PORT}")
    time.sleep(5)
