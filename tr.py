import socket

def trace_route(dest):
    destIP = socket.gethostbyname(dest)
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    ttl = 1
    port = 33435
    max_hop = 64
    while True:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_socket.setsockopt(socket.SOL_IP, socket.SOCK_DGRAM, udp)
        send_sckt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_sckt.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        try:
            recv_socket.bind(('127.0.0.1', port))
        except IOError:
            print("fail to bind")
        send_sckt.sendto(bytes(0), (destIP, port))
        current_address = None
        current_name = None
        try:
            recv_socket.settimeout(100.0)
            data, current_address = recv_socket.recvfrom(2048)
            current_address = current_address[0] # ip地址
            try:
                current_name = socket.gethostbyaddr(current_address)[0]
            except socket.error:
                current_name = "Unknow_name"
        except socket.error:
            pass
        finally:
            send_sckt.close()
            recv_socket.close()
        if current_address is not None:
            current_host = "%s (%s)" % (current_name, current_address)
        else:
            current_host = "*"
        print("%d \t %s" % (ttl, current_host))
        ttl = ttl + 1
        if current_address == destIP or ttl > max_hop:
            break
        pass

trace_route("www.baidu.com")