# -*- coding: utf-8 -*-
'''
 - TUN: IP数据包处理
 - ___: UDP数据包处理
 - ___: DNS数据包处理

'''
class IPPacket:
    '''
    对 TUN 设备收发的 IP 包进行操作
    - 每一位data代表 1byte = 8 bit
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    Example Internet Datagram Header
    '''
    @staticmethod
    def get_version(data):
        '''
        获取版本号, 0-4bit
        '''
        return data[0]>>4


    @staticmethod
    def get_header_length(data):
        '''
        获取首部长度 （单位：word = 4 bytes）, 5-8bit
        '''
        # assert data[0] & 0b1111 == 5
        return data[0] & 0b1111


    @staticmethod
    def get_src(data):
        '''
        获取IP源地址
        '''
        return data[12:16]


    @staticmethod
    def get_dst(data):
        '''
        获取IP目标地址
        '''
        return data[16:20]

    @staticmethod
    def str_info(data):
        '''
        打印关键信息
        '''
        l = list(map(int, data[12:20]))
        return "IP packet from %d.%d.%d.%d to %d.%d.%d.%d"%(l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7])
