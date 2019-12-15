import socket
import sys
import time
import struct
import random

HOST, PORT = "10.60.66.66", 10086
DNS_sever = '120.78.166.34'
domain_name = "group11.cs305.fun"
myserver = '13.57.9.1'
server_port = 53

def make_forward_iphdr(source_ip = '1.0.0.1', dest_ip = '2.0.0.2', proto = socket.IPPROTO_UDP) :
    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = 54321   #Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = proto
    ip_check = 0    # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton ( dest_ip )

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    return ip_header

def make_udphdr(src_port = 1024, dst_port = 10086, udp_segment = bytes('Content-Length:' + '\r\n', 'utf-8')):
    udp_length = 0
    udp_checksum = calc_checksum(udp_segment)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_length, udp_checksum)
    return udp_header

def calc_checksum(msg):
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    #complement and mask to 4 byte short
    s = ~s & 0xffff
    return s

def make_DNSpaket(ip_paket = "Hello, Word"):
    id = random.randint(0, 65535)
    flag = 288
    num_question = 1
    num_answer = 0
    num_authority = 0
    num_addition = 0
    name = domain_name
    type = 1
    _class = 1
    DNS_packet = socket.pack('!HHHHHHsBBs', id, flag, num_question, num_answer, num_authority, num_addition, name, type, _class, ip_paket)
    return DNS_packet
