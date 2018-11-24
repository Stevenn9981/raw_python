#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
#           Copyright 2018 Dept. CSE SUSTech
#           Copyright 2018 Suraj Singh Bisht
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#
# --------------------------------------------------------------------------
#                         Don't Remove Authors Info                        |
# --------------------------------------------------------------------------


__author__ = 'Suraj Singh Bisht, HHQ. ZHANG'
__credit__ = '["Suraj Singh Bisht",]'
__contact__ = 'contact@jinlab.cn'
__copyright__ = 'Copyright 2018 Dept. CSE SUSTech'
__license__ = 'Apache 2.0'
__Update__ = '2018-01-11 12:33:09.399381'
__version__ = '0.1'
__maintainer__ = 'HHQ. ZHANG'
__status__ = 'Production'

import random
import select
# import module
import socket
import time
import struct

from raw_python import ICMPPacket, parse_icmp_header, parse_eth_header, parse_ip_header


def calc_rtt(time_sent):
    return time.time() - time_sent


def catch_ping_reply(s, ID, time_sent, timeout=1):
    # create while loop
    while True:
        starting_time = time.time()  # Record Starting Time

        # to handle timeout function of socket
        process = select.select([s], [], [], timeout)

        # check if timeout
        if not process[0]:
            return calc_rtt(time_sent), None, None

        # receive packet
        rec_packet, addr = s.recvfrom(1024)

        # extract icmp packet from received packet 
        icmp = parse_icmp_header(rec_packet[20:28])

        # check identification
        if icmp['id'] == ID:
            return calc_rtt(time_sent), parse_ip_header(rec_packet[:20]), icmp


def single_ping_request(s, addr=None):
    # Random Packet Id
    pkt_id = random.randrange(10000, 65000)

    # Create ICMP Packet
    packet = ICMPPacket(_id=pkt_id).raw

    # Send ICMP Packet
    while packet:
        sent = s.sendto(packet, (addr, 1))
        packet = packet[sent:]

    return pkt_id


def main():
    # create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # take Input
    addr = input("[+] Enter Domain Name : ") or "www.sustc.edu.cn"
    # print('PING {0} ({1}) 56(84) bytes of data.'.format(addr, socket.gethostbyname(addr)))
    # # Request sent
    # ID = single_ping_request(s, addr)

    # # Catch Reply
    # rtt, reply, icmp_reply = catch_ping_reply(s, ID, time.time())

    # if reply:
    #     reply['length'] = reply['Total Length'] - 20  # sub header
    #     print('{0[length]} bytes reply from {0[Source Address]} ({0[Source Address]}): '
    #           'icmp_seq={1[seq]} ttl={0[TTL]} time={2:.2f} ms'
    #           .format(reply, icmp_reply, rtt*1000))
    try:
        ip = socket.gethostbyname(addr)
    except socket.error:
        print("Not a valid host name")
        sys.exit()

    ttl = traceroute(addr)
    print("%d hops passed." %ttl)
    # close socket
    s.close()
    return

def checksum(source):
    """ Calculates a checksum for source to be used in network communications
    :param source: the input to calculate the checksum for
    :return: the calculated checksum
    """
    checksum_return = 0
    length = len(source)

    for char in range(0, length, 2):
        if char + 1 == length:
            checksum_return += to_digit(source[char])
            break
        checksum_return += (to_digit(source[char + 1]) << 8) + to_digit(source[char])

    checksum_return = (checksum_return >> 16) + (checksum_return & 0xffff)
    checksum_return += (checksum_return >> 16)
    checksum_return = ~checksum_return

    return checksum_return & 0xffff

def to_digit(value):
    """ Converts a value to be numeric
    :param value: the value to be converted to a number
    :return: the value itself it is already a number, else the
            numeric form of the value
    """
    if isinstance(value, int):
        return value

    return ord(value)

def traceroute(destination, max_hops=50, timeout=1):
    """ Calculates the number of hops required to reach the given destination
    :param destination: the hostname being traced
    :param max_hops: the max number of hops to be completed
    :param timeout: the max time to wait for a response after sending a packet
    :return: a tuple containing the number of hops and the time taken to complete
            the final hop
    """
    ttl = 1
    start_time = 0
    end_time = 0
    ti = 0
    times = list()
    print()
    while ttl < max_hops:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        except socket.error:
            print("oh no")
            sys.exit()

        destination = socket.gethostbyname(destination)
        icmp_checksum = 0
        header = struct.pack("BBHHH", 0, 0, icmp_checksum, 0, 0)
        icmp_checksum = checksum(header)
        header = struct.pack("BBHHH", 0, 0, icmp_checksum, 0, 0)

        sock.sendto(header, (socket.gethostbyname(destination), 1))

        try:
            start_time = time.clock()
            data, address = sock.recvfrom(1024)
            end_time = time.clock()
        except socket.timeout:
            times.append("*")
            ti += 1
            if ti == 3:
                ti = 0
                print("%5d %-20s%-20s%-20s%-20s" %(ttl, "*", times[0], times[1], times[2]))
                times = list()
                ttl += 1
            continue
        except socket.error:
            print("this is fine")
            sys.exit()
        finally:
            sock.close()


        if address:
            # print(address[0])
            if address[0] == destination:
                break
        times.append(str(round(1000*(end_time - start_time),2)) + " ms")
        ti += 1
        if ti == 3:
            ti = 0
            print("%5d %-20s%-20s%-20s%-20s" %(ttl, address[0], str(times[0]), str(times[1]), str(times[2])))
            times = list()
            ttl += 1

    return ttl

if __name__ == '__main__':
    main()
