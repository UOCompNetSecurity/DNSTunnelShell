from dataclasses import dataclass, field
from enum import Enum

class PrinterMessageType(Enum): 
    ERROR = 1,
    SENT = 2,
    RECEIVED = 3
    PROBE = 4,
    FILE_START = 5,
    FILE_END = 6
    CONN = 7

@dataclass 
class PrinterMessage: 
    message_type: PrinterMessageType
    message: str = field(default="")
    





        
