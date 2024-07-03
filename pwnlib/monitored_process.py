# -*- coding: utf-8 -*-
from __future__ import absolute_import

from pwnlib import gdb
from pwnlib import tubes
from pwnlib.log import Logger

import logging

__all__ = ['monitored_process']

class monitored_process(Logger):
    def __init__(self, pattern: bytes, address: int, *args, **kwargs):
        """Monitors a process for a pattern in the communication stream and breakpoints at an address when this pattern is detected.

        Args:
            pattern (bytes): A pattern to search for in the communication stream.
            address (int): The address to break at when the pattern is detected.
        """
        self.pattern = pattern
        self.address = address
        self.proc = tubes.process.process(*args, **kwargs)

        Logger.__init__(self, None)
        self.setLevel(logging.DEBUG)
        
        # Attach GDB to the process
        self.gdb_pid,self.gdb = gdb.attach(self.proc, exe=self.proc.argv[0], gdbscript="continue", api=True)
    
    def sendline(self, data: bytes):
        """Send a line to the process.

        Args:
            data (bytes): The data to send.
        """
        self.debug("Sending data:")
        self.maybe_hexdump(data, level=logging.DEBUG)
        self.proc.sendline(data)
    
    def recvline(self, *args, **kwargs) -> bytes:
        """Receive a line from the process.

        Returns:
            bytes: The data received from the process.
        """
        data = self.proc.recvline(*args, **kwargs)
        self.debug("Received data:")
        self.maybe_hexdump(data, level=logging.DEBUG)
        
        # Monitor for pattern
        if self.pattern in data:
            self.debug(f"Pattern detected: {self.pattern}")
            command = 'break *0x%x' %self.address 
            self.debug(command)
            self.gdb.execute('break *0x%x' %self.address )
        
        return data
