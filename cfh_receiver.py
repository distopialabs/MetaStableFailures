import socket
import struct

UDP_IP = "127.0.0.1"
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

CFH_STRUCT_FORMAT = "! B I I B B I I I Q"
CFH_SIZE = struct.calcsize(CFH_STRUCT_FORMAT)

print("Listening for CFH packets...")

while True:
    data, addr = sock.recvfrom(1024)
    if len(data) < CFH_SIZE:
        print(f"Received packet too small: {len(data)} bytes")
        continue

    (version, length, request_id, ttl, signal, d_host_id, rdma_host_id, rkey,
     mr_base_addr) = struct.unpack(CFH_STRUCT_FORMAT, data[:CFH_SIZE])

    print(f"Received CFH from {addr}:")
    print(f"  version={version}, ttl={ttl}, signal={signal}")
    print(f"  d_host_id={d_host_id}, rdma_host_id={rdma_host_id}")
    print(f"  rkey=0x{rkey:x}, mr_base_addr=0x{mr_base_addr:x}, length={length}")
    print(f"  request_id={request_id}")
