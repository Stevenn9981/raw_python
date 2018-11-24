import os
import sys
import socket
import struct
import time


def to_digit(value):
    """ Converts a value to be numeric
    :param value: the value to be converted to a number
    :return: the value itself it is already a number, else the
            numeric form of the value
    """
    if isinstance(value, int):
        return value

    return ord(value)


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
    while ttl <= max_hops:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        except socket.error:
            print("oh no")
            sys.exit()

        destination = socket.gethostbyname(destination)
        icmp_checksum = 0
        header = struct.pack("BBHHH", 8, 0, icmp_checksum, 0, 0)
        icmp_checksum = checksum(header)
        header = struct.pack("BBHHH", 8, 0, icmp_checksum, 0, 0)

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
        		print("%2d     %-20s%-20s%-20s%-20s" %(ttl, "*", times[0], times[1], times[2]))
        		times = list()
        		ttl += 1
        	continue
        except socket.error:
            print("this is fine")
            sys.exit()
        finally:
            sock.close()

        times.append(str(round(1000*(end_time - start_time),2)) + " ms")
        ti += 1
        if ti == 3:
            ti = 0
            print("%2d     %-20s%-20s%-20s%-20s" %(ttl, address[0], str(times[0]), str(times[1]), str(times[2])))
            times = list()
            ttl += 1

        if address:
            # print(address[0])
            if address[0] == destination and ti == 0:
                break

    return ttl - 1


def main():

    host = sys.argv[1]
    ttl = traceroute(host)
    print("%d hops passed" %(ttl))

if __name__ == '__main__':
    main()
