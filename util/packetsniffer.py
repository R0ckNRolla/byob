#!/usr/bin/python
import socket
import os
import sys
import struct
import binascii


def analyze_udp_header(data):
    try:
        udp_hdr = struct.unpack('!4H', data[:8])
        src     = udp_hdr[0]
        dst     = udp_hdr[1]
        length  = udp_hdr[2]
        chksum  = udp_hdr[3]
        data    = data[8:]
        print '|================== UDP HEADER ==================|'
	print '|================================================|'
        print '|{:>20} | {}\t\t\t |'.format('Source', src)
        print '|{:>20} | {}\t\t\t |'.format('Dest', dst)
        print '|{:>20} | {}\t\t\t |'.format('Length', length)
        print '|{:>20} | {}\t\t\t |'.format('Check Sum', chksum)
	print '|================================================|'
        return data
    except Exception as e:
        print "Error in {} header: '{}'".format('UDP', str(e))

def analyze_tcp_header(recv_data):
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

        print '|================== TCP HEADER ==================|'
	print '|================================================|'
        print '|{:>20} | {}\t\t\t |'.format('Source', src_port)
        print '|{:>20} | {}\t\t\t |'.format('Target', dst_port)
        print '|{:>20} | {}\t\t\t |'.format('Seq Num', seq_num)
        print '|{:>20} | {}\t\t |'.format('Ack Num', ack_num)
	print '|{:>20} | {}\t\t |'.format('Flags', ', '.join([flag for flag in flagdata if flagdata.get(flag)]))
        print '|{:>20} | {}\t\t\t |'.format('Window', win)
        print '|{:>20} | {}\t\t\t |'.format('Check Sum', chk_sum)
        print '|{:>20} | {}\t\t\t |'.format('Urg Pnt', urg_pnt)
	print '|================================================|'
        return recv_data
    except Exception as e:
        print "Error in {} header: '{}'".format('TCP', str(e))

def analyze_ip_header(data):
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

        print '|================== IP HEADER ===================|'
	print '|================================================|' 
	print '|{:>20} | {}\t\t\t{}'.format('VER', ver, ' |')
        print '|{:>20} | {}\t\t\t{}'.format('IHL', ihl, ' |')
        print '|{:>20} | {}\t\t\t{}'.format('TOS', tos, ' |')
        print '|{:>20} | {}\t\t\t{}'.format('Length', tot_len, ' |')
        print '|{:>20} | {}\t\t\t{}'.format('ID', ip_id, ' |')
        print '|{:>20} | {}\t\t\t{}'.format('Flags', flags, ' |')
        print '|{:>20} | {}\t\t\t{}'.format('Frag Offset', fragofs, ' |')
        print '|{:>20} | {}\t\t\t{}'.format('TTL', ttl, ' |')
        print '|{:>20} | {}\t\t\t{}'.format('Next Protocol', ipproto, ' |')
        print '|{:>20} | {}\t\t\t{}'.format('Check Sum', chksum, ' |')
        print '|{:>20} | {}\t\t{}'.format('Source IP', src, ' |')
        print '|{:>20} | {}\t\t{}'.format('Dest IP', dest, ' |')
	print '|================================================|'

        return data, ipproto
    except Exception as e:
        print "Error in {} header: '{}'".format('IP', str(e))


def analyze_ether_header(data):
    try:
        ip_bool = False
        eth_hdr = struct.unpack('!6s6sH', data[:14])
        dst_mac = binascii.hexlify(eth_hdr[0])
        src_mac = binascii.hexlify(eth_hdr[1])
        proto   = eth_hdr[2] >> 8

	print '|================================================|'
        print '|================== ETH HEADER ==================|'
	print '|================================================|'
        print '|{:>20} | {}\t{}'.format('Target MAC', '{}:{}:{}:{}:{}:{}'.format(dst_mac[0:2],dst_mac[2:4],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:12]), ' |')
        print '|{:>20} | {}\t{}'.format('Source MAC', '{}:{}:{}:{}:{}:{}'.format(src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12]), ' |')
        print '|{:>20} | {}\t\t\t{}'.format('Protocol', proto, ' |')
	print '|================================================|'

        if proto == 8:
            ip_bool = True
        data = data[14:]
        return data, ip_bool
    except Exception as e:
        print "Error in {} header: '{}'".format('ETH', str(e))


def main():
    print 
    print 'Listening for incoming packets on all ports...'
    print
    print '     (press ctrl-c anytime to stop)'
    print
    sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    while sniffer_socket:
        try:
            recv_data = sniffer_socket.recv(2048)
            os.system('clear')
            recv_data, ip_bool = analyze_ether_header(recv_data)
            if ip_bool:
                recv_data, ip_proto = analyze_ip_header(recv_data)
                if ip_proto == 6:
                    recv_data = analyze_tcp_header(recv_data)
                elif ip_proto == 17:
                    recv_data = analyze_udp_header(recv_data)
        except KeyboardInterrupt:
            if raw_input('Quit packetsniffer? (y/n): ').lower().startswith('y'):
                sys.exit(0)
            else:
                continue

if __name__ == '__main__':
    if os.name is 'posix':
        main()
    else:
        print 'Packetsniffer is not compatible with Windows-based platforms'
        sys.exit(0)
