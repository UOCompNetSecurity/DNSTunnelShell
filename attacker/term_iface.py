


import curses
from printer_message import PrinterMessage, PrinterMessageType
import time 
import queue
from enum import Enum

class BuiltInCommand(Enum): 
    CLEAR = 1

class TerminalIFace:
    def __init__(self, stdscr, command_queue: queue.Queue[str], print_queue: queue.Queue[PrinterMessage]):
        self.stdscr = stdscr
        self.command_queue = command_queue
        self.print_queue = print_queue

        self.input_buffer = ""
        self.received_buffer = ""

        curses.noecho()
        stdscr.clear()

        # Draw Windows 
        height, width = stdscr.getmaxyx()
        mid_x = width // 3

        self.left_win  = curses.newwin(height, mid_x, 0, 0)
        self.right_win = curses.newwin(height, width - mid_x, 0, mid_x)

        self.left_win.box()
        self.right_win.box()

        self.left_win.addstr(1, 3, "DNS Tunneled Shell")

        input_height = 3
        input_width = mid_x - 4
        input_y = 2
        input_x = 2

        self.input_frame = self.left_win.derwin(
            input_height, input_width, input_y, input_x
        )
        self.input_frame.box()

        self.input_area = self.input_frame.derwin(
            1, input_width - 2, 1, 1
        )

        self.input_area.nodelay(True)

        self.cur_right_win_y = 1
        self.cur_left_win_y = input_height + input_y + 1
        self.start_right_win_y = self.cur_right_win_y
        self.start_left_win_y = self.cur_left_win_y

        # Setup Colors

        curses.start_color()
        curses.use_default_colors()

        self.green = 1
        self.yellow = 2
        self.red = 3
        self.cyan = 4

        curses.init_pair(self.green, curses.COLOR_GREEN, -1)
        curses.init_pair(self.yellow, curses.COLOR_YELLOW, -1)
        curses.init_pair(self.red, curses.COLOR_RED, -1)
        curses.init_pair(self.cyan, curses.COLOR_CYAN, -1)

        self.left_win.refresh()
        self.right_win.refresh()
        self.input_frame.refresh()
        self.input_area.refresh()

    def run(self):
        while True:
            self.input_area.refresh()
            while not self.print_queue.empty(): 
                message = self.print_queue.get()
                match message.message_type: 
                    case PrinterMessageType.CONN: 
                        self._print_conn()
                    case PrinterMessageType.RECEIVED: 
                        self.received_buffer += message.message
                    case PrinterMessageType.SENT: 
                        self._print_sent(message.message)
                    case PrinterMessageType.ERROR: 
                        self._print_error(message.message)
                    case PrinterMessageType.PROBE: 
                        self._print_probe("PROBE")
                    case PrinterMessageType.FILE_START: 
                        self.received_buffer = ""
                    case PrinterMessageType.FILE_END: 
                        self._print_received(self.received_buffer)
                        self.received_buffer = ""

            input = self._get_input().strip()
            if input: 
                if input.startswith('!'): 
                    built_in_command = input[1:]
                    match built_in_command.upper(): 
                        case BuiltInCommand.CLEAR.name: 
                            self._reset_right_window()
                else: 
                    self.command_queue.put(input)
                    self._print_queued(input)

            time.sleep(0.02)
                

    def _get_input(self) -> str: 
        ch = self.input_area.getch()
        if ch == -1: 
            return ""

        if ch in (curses.KEY_ENTER, 10, 13): 
            cmd = self.input_buffer
            self.input_buffer = ""
            self._draw_input()
            return cmd

        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if self.input_buffer: 
                self.input_buffer = self.input_buffer[:-1]
            self._draw_input()

        elif 32 <= ch <= 126:
            self.input_buffer += chr(ch)
            self._draw_input()

        return ""

    def _draw_input(self): 
        self.input_area.erase()

        height, width  = self.input_area.getmaxyx()

        visible = self.input_buffer[-(width - 1):]

        self.input_area.addstr(visible)

        self.input_area.move(0, min(len(visible), width - 1))

        self.input_area.refresh()


    def _get_window_text(self, win):
        height, width = win.getmaxyx()
        lines = []
        for y in range(height):
            line_bytes = win.instr(y, 0)  
            line = line_bytes.decode('utf-8').rstrip()  
            lines.append(line)
        return lines

    def _reset_left_window(self): 
        self.cur_left_win_y = self.start_left_win_y
        self.left_win.erase()
        self.left_win.box()
        self.left_win.addstr(1, 3, "DNS Tunneled Shell")
        self.input_frame.box()
        self.left_win.refresh()
        self.input_frame.refresh()

    def _reset_right_window(self): 
        self.cur_right_win_y = self.start_right_win_y
        self.right_win.erase()
        self.right_win.box()
        self.right_win.refresh()

    def _print_message(self, window, y, message, symbol, color): 

        cur_y, cur_x = self.input_area.getyx()

        window.addstr(y, 1, f"[{symbol}] {message}", curses.color_pair(color))

        window.refresh()

        self.input_area.move(cur_y, cur_x)

        self.input_area.refresh()

    def _split_lines(self, message: str, width: int): 
        cur_ch_line = 0
        seperated = []

        seperated_start = 0
        for i, ch in enumerate(message): 
            if cur_ch_line >= width - 2: 
                seperated.append(message[seperated_start:i - 5])
                seperated_start = i - 1
                cur_ch_line = 0 

            if ch == '\n': 
                cur_ch_line = 0
            else: 
                cur_ch_line += 1

        seperated.append(message[seperated_start:len(message)])

        for i in range(len(seperated)): 
            seperated[i] = seperated[i] + '\n'

        glued = ""
        for message in seperated: 
            glued += message

        output = glued.splitlines()

        return output


    def _print_right_win(self, message: str, symbol: str, color: int): 
        height, width = self.right_win.getmaxyx()
        lines = self._split_lines(message, width)
        if len(lines) + self.cur_right_win_y >= height - 1: 
            self._reset_right_window()
            self.cur_right_win_y = self.start_right_win_y
        for line in lines: 
            self._print_message(self.right_win, self.cur_right_win_y, line, symbol, color)
            self.cur_right_win_y += 1

    def _print_left_win(self, message: str, symbol: str, color: int): 
        height, width = self.left_win.getmaxyx()
        lines = self._split_lines(message, width)
        if len(lines) + self.cur_left_win_y >= height - 1: 
            self._reset_left_window()
            self.cur_left_win_y = self.start_left_win_y
        for line in lines:
            self._print_message(self.left_win, self.cur_left_win_y, line, symbol, color)
            self.cur_left_win_y += 1


    def _print_received(self, message: str):
        self._print_right_win(message, "+", self.green)

    def _print_probe(self, message: str):
        self._print_right_win(message, "*", self.cyan)

    def _print_sent(self, message: str):
        self._print_left_win(f"Sent: {message}", "+", self.green)

    def _print_conn(self):
        self._print_left_win(f"Client Connected", "+", self.green)

    def _print_queued(self, message: str):
        self._print_left_win(f"Command Queued: {message}", "+", self.yellow)

    def _print_error(self, message: str):
        self._print_left_win(f"Error: {message}", "!", self.red)


