#!/usr/bin/python
import os
import sys
import struct
import socket
import binascii

packet_buffer = []


def packetsniffer_udp_header(data):
    global packet_buffer
    try:
        udp_hdr = struct.unpack('!4H', data[:8])
        src     = udp_hdr[0]
        dst     = udp_hdr[1]
        length  = udp_hdr[2]
        chksum  = udp_hdr[3]
        data    = data[8:]
        packet_buffer.append('|================== UDP HEADER ==================|')
	packet_buffer.append('|================================================|')
        packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Source', src))
        packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Dest', dst))
        packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Length', length))
        packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chksum))
	packet_buffer.append('|================================================|')
        return data
    except Exception as e:
        packet_buffer.append("Error in {} header: '{}'".format('UDP', str(e)))

def packetsniffer_tcp_header(recv_data):
    global packet_buffer
    try:
        tcp_hdr  = struct.unpack('!2H2I4H', recv_data[:20])
        src_port = tcp_hdr[0]
        dst_port = tcp_hdr[1]
        seq_num  = tcp_hdr[2]
        ack_num  = tcp_hdr[3]
        data_ofs = tcp_hdr[4] >> 12
        reserved = (tcp_hdr[4] >> 6) & 0x03ff
        flags    = tcp_hdr[4] & 0x003f
	flagdata = {
		'URG' : bool(flags & 0x0020),
        	'ACK' : bool(flags & 0x0010),
       		'PSH' : bool(flags & 0x0008),
        	'RST' : bool(flags & 0x0004),
        	'SYN' : bool(flags & 0x0002),
        	'FIN' : bool(flags & 0x0001)
		}
        win = tcp_hdr[5]
        chk_sum = tcp_hdr[6]
        urg_pnt = tcp_hdr[7]
        recv_data = recv_data[20:]

        packet_buffer.append('|================== TCP HEADER ==================|')
	packet_buffer.append('|================================================|')
        packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Source', src_port))
        packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Target', dst_port))
        packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Seq Num', seq_num))
        packet_buffer.append('|{:>20} | {}\t\t |'.format('Ack Num', ack_num))
	packet_buffer.append('|{:>20} | {}\t\t |'.format('Flags', ', '.join([flag for flag in flagdata if flagdata.get(flag)])))
        packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Window', win))
        packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Check Sum', chk_sum))
        packet_buffer.append('|{:>20} | {}\t\t\t |'.format('Urg Pnt', urg_pnt))
	packet_buffer.append('|================================================|')
        return recv_data
    except Exception as e:
        packet_buffer.append("Error in {} header: '{}'".format('TCP', str(e)))

def packetsniffer_ip_header(data):
    global packet_buffer
    try:
        ip_hdr  = struct.unpack('!6H4s4s', data[:20]) 
        ver     = ip_hdr[0] >> 12
        ihl     = (ip_hdr[0] >> 8) & 0x0f
        tos     = ip_hdr[0] & 0x00ff 
        tot_len = ip_hdr[1]
        ip_id   = ip_hdr[2]
        flags   = ip_hdr[3] >> 13
        fragofs = ip_hdr[3] & 0x1fff
        ttl     = ip_hdr[4] >> 8
        ipproto = ip_hdr[4] & 0x00ff
        chksum  = ip_hdr[5]
        src     = socket.inet_ntoa(ip_hdr[6])
        dest    = socket.inet_ntoa(ip_hdr[7])
        data    = data[20:]

        packet_buffer.append('|================== IP HEADER ===================|')
	packet_buffer.append('|================================================|')
	packet_buffer.append('|{:>20} | {}\t\t\t{}'.format('VER', ver, ' |'))
        packet_buffer.append('|{:>20} | {}\t\t\t{}'.format('IHL', ihl, ' |'))
        packet_buffer.append('|{:>20} | {}\t\t\t{}'.format('TOS', tos, ' |'))
        packet_buffer.append('|{:>20} | {}\t\t\t{}'.format('Length', tot_len, ' |'))
        packet_buffer.append('|{:>20} | {}\t\t\t{}'.format('ID', ip_id, ' |'))
        packet_buffer.append('|{:>20} | {}\t\t\t{}'.format('Flags', flags, ' |'))
        packet_buffer.append('|{:>20} | {}\t\t\t{}'.format('Frag Offset', fragofs, ' |'))
        packet_buffer.append('|{:>20} | {}\t\t\t{}'.format('TTL', ttl, ' |'))
        packet_buffer.append('|{:>20} | {}\t\t\t{}'.format('Next Protocol', ipproto, ' |'))
        packet_buffer.append('|{:>20} | {}\t\t\t{}'.format('Check Sum', chksum, ' |'))
        packet_buffer.append('|{:>20} | {}\t\t{}'.format('Source IP', src, ' |'))
        packet_buffer.append('|{:>20} | {}\t\t{}'.format('Dest IP', dest, ' |'))
	packet_buffer.append('|================================================|')
        return data, ipproto
    except Exception as e:
        packet_buffer.append("Error in {} header: '{}'".format('IP', str(e)))


def packetsniffer_ethernet_header(data):
    global packet_buffer
    try:
        ip_bool = False
        eth_hdr = struct.unpack('!6s6sH', data[:14])
        dst_mac = binascii.hexlify(eth_hdr[0])
        src_mac = binascii.hexlify(eth_hdr[1])
        proto   = eth_hdr[2] >> 8

	packet_buffer.append('|================================================|')
        packet_buffer.append('|================== ETH HEADER ==================|')
	packet_buffer.append('|================================================|')
        packet_buffer.append('|{:>20} | {}\t{}'.format('Target MAC', '{}:{}:{}:{}:{}:{}'.format(dst_mac[0:2],dst_mac[2:4],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:12]), ' |'))
        packet_buffer.append('|{:>20} | {}\t{}'.format('Source MAC', '{}:{}:{}:{}:{}:{}'.format(src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12]), ' |'))
        packet_buffer.append('|{:>20} | {}\t\t\t{}'.format('Protocol', proto, ' |'))
	packet_buffer.append('|================================================|')

        if proto == 8:
            ip_bool = True
        data = data[14:]
        return data, ip_bool
    except Exception as e:
        packet_buffer.append("Error in {} header: '{}'".format('ETH', str(e)))


def packetsniffer():
    global packet_buffer
    if os.name is 'posix':
        return 'Packetsniffer is not compatible with Windows-based platforms'
    sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    while sniffer_socket:
        try:
            recv_data = sniffer_socket.recv(2048)
            recv_data, ip_bool = packetsniffer_ethernet_header(recv_data)
            if ip_bool:
                recv_data, ip_proto = packetsniffer_ip_header(recv_data)
                if ip_proto == 6:
                    recv_data = packetsniffer_tcp_header(recv_data)
                elif ip_proto == 17:
                    recv_data = packetsniffer_udp_header(recv_data)
        except KeyboardInterrupt:
            break
    return '\n'.join(packet_buffer)


