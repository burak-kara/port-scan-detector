#!/usr/bin/env python
"""
pyscanlogger3: Simple port scan detector/logger tool in python3, inspired
by pyscanlogger {https://github.com/John-Lin/pyscanlogger}
"""

import os
import sys
import stat
import time
import dpkt
import pcap
import struct
import socket
from datetime import datetime
import optparse

SCAN_TIMEOUT = 5  # as ms
WEIGHT_THRESHOLD = 25
PIDFILE = "./pyscanlogger.pid"

# tcp control flag constants
TH_FIN = dpkt.tcp.TH_FIN  # end of data 01
TH_SYN = dpkt.tcp.TH_SYN  # synchronize sequence numbers 02
TH_RST = dpkt.tcp.TH_RST  # reset connection 04
TH_PSH = dpkt.tcp.TH_PUSH  # push 08
TH_ACK = dpkt.tcp.TH_ACK  # acknowledgment number set 10
TH_URG = dpkt.tcp.TH_URG  # urgent pointer set 20

# Protocols
TCP = dpkt.tcp.TCP
UDP = dpkt.udp.UDP

get_timestamp = lambda t: datetime.fromtimestamp(t)


class ScanEntry(object):
    """ Port scan entry """

    def __init__(self, hash):
        self.src = 0
        self.dst = 0
        self.timestamp = 0
        self.logged = False
        self.type = ''
        self.tcpflags_or = 0
        self.weight = 0
        self.ports = []
        self.next = None
        self.hash = hash


class EntryLog(dict):
    """ Modified dictionary class with fixed size, which
    automatically removes the oldest items """

    # This will work only if the value is an object storing
    # its key in the 'hash' attribute and links to other
    # objects using the 'next' attribute.
    def __init__(self, max_size):
        self.oldest = None
        self.last = None
        self.max_size = max_size
        super(EntryLog, self).__init__()

    def __setitem__(self, key, value):
        if not self.__contains__(key) and len(self) == self.max_size:
            # Remove oldest
            if self.oldest:
                self.__delitem__(self.oldest.hash)
                self.oldest = self.oldest.next

        super(EntryLog, self).__setitem__(key, value)

        if self.last:
            self.last.next = value
            self.last = value
        else:
            self.last = value
            self.oldest = self.last


class TimerList(list):
    """ List class of fixed size with entries that time out automatically """

    def __getattribute__(self, name):
        if name in ('insert', 'pop', 'extend'):
            raise NotImplementedError
        else:
            return super(TimerList, self).__getattribute__(name)

    def __init__(self, max_size, ttl):
        # Maximum size
        self.max_size = max_size
        # Time to live for every entry
        self.ttl = ttl

    def append(self, item):
        """ Append an item to end """

        if len(self) < self.max_size:
            # We append the time-stamp with the item
            super(TimerList, self).append((time.time(), item))
        else:
            n = self.collect()
            if n:
                # Some items removed, so append
                super(TimerList, self).append((time.time(), item))
            else:
                raise ValueError('could not append item')

    def collect(self):
        """ Collect and remove aged items """

        t = time.time()
        old = []
        for item in self:
            if (t - item[0]) > self.ttl:
                old.append(item)

        for item in old:
            self.remove(item)

        return len(old)

    # Access functions
    def __getitem__(self, index):
        item = super(TimerList, self).__getitem__(index)
        return item[1]

    def __setitem__(self, index, item):
        # Allow only tuples with time-stamps >= current time-stamp as 1st member
        if type(item) == tuple and len(item) == 2 and type(item[0]) == float and item[0] >= time.time():
            super(TimerList, self).__setitem__(index, item)
        else:
            raise TypeError('invalid entry')

    def __contains__(self, item):
        items = [rest for (tstamp, rest) in self]
        return item in items


class ScanLogger(object):
    """ Port scan detector """

    # TCP flags to scan type mapping
    scan_types = {0: 'TCP NULL',
                  TH_FIN: 'TCP FIN',
                  TH_SYN: 'TCP SYN',
                  TH_ACK: 'TCP ACK',
                  TH_SYN | TH_RST: 'TCP SYN/RST',
                  TH_SYN | TH_FIN: 'TCP SYN/FIN',
                  TH_FIN | TH_ACK: 'TCP FIN/ACK',
                  TH_URG | TH_PSH | TH_FIN: 'TCP x-mas',
                  TH_SYN | TH_ACK | TH_RST: 'TCP full-connect',
                  TH_URG | TH_PSH | TH_FIN | TH_ACK: 'TCP x-mas',
                  TH_URG | TH_PSH | TH_ACK | TH_RST | TH_SYN | TH_FIN: 'TCP all-flags'}

    def __init__(self, timeout, threshold, maxsize):
        self.scans = EntryLog(maxsize)
        # Port scan weight threshold
        self.threshold = threshold
        # Timeout for scan entries
        self.timeout = timeout
        # Daemonize ?
        self.daemon = True
        # Log file
        try:
            self.scanlog = open('./scanlog', 'a')
        except (IOError, OSError) as e:
            print("Error opening scan log file", e)
            self.scanlog = None

        # Recent scans - this list allows to keep scan information
        # upto last 'n' seconds, so as to not call duplicate scans
        # in the same time-period. 'n' is 60 sec by default.

        # Since entries time out in 60 seconds, max size is equal
        # to maximum such entries possible in 60 sec - assuming
        # a scan occurs at most every 5 seconds, this would be 12.
        self.recent_scans = TimerList(12, 60.0)

    def hash_func(self, addr):
        """ Hash a host address """
        value = addr
        h = 0

        while value:
            # print value
            h ^= value
            value = value >> 9

        return h & (8192 - 1)

    def host_hash(self, src, dst):
        """ Hash mix two host addresses """
        return self.hash_func(src) ^ self.hash_func(dst)

    def log_scan(self, scan):
        """ Log the scan to file"""
        src_ip, dst_ip = socket.inet_ntoa(struct.pack('I', scan.src)), socket.inet_ntoa(struct.pack('I', scan.dst))

        line = '[%s]: %s %s' % (get_timestamp(scan.timestamp), src_ip, scan.type)

        if self.scanlog:
            self.scanlog.write(line + '\n')
            self.scanlog.flush()

    @staticmethod
    def get_info(ip, pload):
        return int(struct.unpack('I', ip.src)[0]), int(struct.unpack('I', ip.dst)[0]), int(pload.dport)

    @staticmethod
    def get_flags(proto, pload):
        if proto == TCP:
            return pload.flags
        return 0

    def process(self, pkt):
        if not hasattr(pkt, 'ip'):
            return

        ip = pkt.ip
        # Ignore non-tcp, non-udp packets
        if type(ip.data) not in (TCP, UDP):
            return

        pload = ip.data
        src, dst, dport = self.get_info(ip, pload)
        proto = type(pload)
        flags = self.get_flags(proto, pload)
        key = self.host_hash(src, dst)
        curr = time.time()
        # Keep dropping old entries
        self.recent_scans.collect()

        if key in self.scans:
            # print("key in scans", flags)
            scan = self.scans[key]

            if scan.src != src:
                # Skip packets in reverse direction or invalid protocol
                return

            # Update only if not too old, else skip and remove entry
            if curr - scan.timestamp > self.timeout:
                del self.scans[key]
                return

            if scan.logged:
                return

            # Update TCP flags if existing port
            if dport in scan.ports:
                # Same port, update flags
                scan.tcpflags_or |= flags
                return

            scan.timestamp = curr
            scan.tcpflags_or |= flags
            scan.ports.append(dport)

            # Add weight for port
            # Ports < 1024 can be used only by root
            # Therefore, they have more weight
            if dport < 1024:
                scan.weight += 2
            else:
                scan.weight += 1

            if scan.weight >= self.threshold:
                scan.logged = True
                if proto == TCP:
                    scan.type = scan.type + " " + self.scan_types.get(scan.tcpflags_or, "TCP")
                elif proto == UDP:
                    scan.type = scan.type + " " + 'UDP'
                    # Reset flags for UDP scan
                    scan.tcpflags_or = 0

                # See if this was logged recently
                scanentry = (key, scan.type, scan.tcpflags_or)

                self.log_scan(scan)
                if scanentry not in self.recent_scans:
                    self.recent_scans.append(scanentry)
        else:
            # print("new", flags)
            # Add new entry
            scan = ScanEntry(key)
            scan.src = src
            scan.dst = dst
            scan.timestamp = curr
            scan.tcpflags_or |= flags
            scan.ports.append(dport)
            self.scans[key] = scan

    def log(self):
        pc = pcap.pcap()
        decode = {pcap.DLT_LOOP: dpkt.loopback.Loopback,
                  pcap.DLT_NULL: dpkt.loopback.Loopback,
                  pcap.DLT_EN10MB: dpkt.ethernet.Ethernet}[pc.datalink()]

        print('listening on %s: %s' % (pc.name, pc.filter))
        for ts, pkt in pc:
            self.process(decode(pkt))

    def run_daemon(self):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            print(sys.stderr, "fork #1 failed", e)
            sys.exit(1)

        os.setsid()
        # os.umask(0)

        # Second fork
        try:
            pid = os.fork()
            if pid > 0:
                open(PIDFILE, 'w').write(str(pid))
                # make pid file only writable and readable by root.
                os.chmod(PIDFILE, stat.S_IREAD | stat.S_IWRITE)
                sys.exit(0)
        except OSError as e:
            print(sys.stderr, "fork #2 failed", e)
            sys.exit(1)

        self.log()


def main():
    if os.geteuid() != 0:
        sys.exit("You must have root privileges to run this daemon")
    s = ScanLogger(SCAN_TIMEOUT, WEIGHT_THRESHOLD, 8192)
    print('Starting the daemon...')
    s.run_daemon()


if __name__ == '__main__':
    try:
        while True:
            try:
                main()
            except TypeError as e:
                time.sleep(0.25)
                print("Continue to start the Pyscanlogger3", e)
                continue
    except KeyboardInterrupt:
        print("Stop the Pyscanlogger!")
