# -*- coding: utf-8 -*-
'''
DNS 相关操作
'''
import struct
from dnslib import (DNSRecord, DNSHeader, DNSQuestion,
                    QTYPE, RR, TXT)

# DNSQuestion:https://juejin.im/post/5ab719c151882577b45ef9d9

class Encapsulator:
    '''
    将数据封装至DNS包中
    '''
    @staticmethod
    def response_str_in_txt(request, data: str):
        '''
        将字符串包装在TXT记录里作为结果返回
        return: bytes
        '''
        print('\n======================================\n')
        request = DNSRecord.parse(request)
        print('REQUEST:\n', request)
        qname = request.q.qname
        qtype = request.q.qtype
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        reply.add_answer(RR(qname, qtype, rdata=TXT(data)))
        print('RESPONSE:\n', reply)
        return reply.pack()

    @staticmethod
    def response_bytes_in_txt(request, data: bytes):
        '''
        将字节流包装在TXT记录里作为结果返回
        return: bytes
        '''
        assert len(data) < 256
        request = DNSRecord.parse(request)
        qname = request.q.qname
        qtype = request.q.qtype
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        reply.add_answer(RR(qname, qtype, rdata=TXT('')))
        reply = reply.pack()
        reply[-3:-1] = struct.pack('>H', len(data) + 1)
        reply[-1] = len(data)
        reply += data
        return reply

    @staticmethod
    def __split_with_length(data: bytes, length: int = 63):
        data_segments = []
        _idx = 0
        _len = len(data)
        while True:
            if _idx + length >= _len:
                data_segments.append(data[_idx: _len])
                break
            data_segments.append(data[_idx: _idx+length])
            _idx += length
        return data_segments

    @staticmethod
    def make_fake_request(_uuid: str, data, host_name):
        '''
        进行伪装查询
        0        12     49
        | header | UUID |
        '''
        assert len(data) <= 63*3
        data_segments = Encapsulator.__split_with_length(data, 63)
        request_msg = DNSRecord()
        request_msg.add_question(DNSQuestion(_uuid+'.'+host_name, QTYPE.TXT))
        request_data = request_msg.pack()
        _idx = 13 + len(_uuid)
        modified_data = request_data[:_idx]
        for data_seg in data_segments:
            data_len = struct.pack('>B', len(data_seg))
            modified_data += data_len + data_seg
        modified_data += request_data[_idx:]
        return modified_data

class Decapsulator:
    '''
    解析DNS数据包
    '''
    TXT = 16
    IN = 1
    @staticmethod
    def get_host_name(packet: bytes)->list:
        '''
        传入DNS数据包，解析主机名
        '''
        # Header 12 byte
        _header = packet[:12]
        # Question Qname + Qtype(2 byte) + Qclass (2byte)
        packet = packet[12:]
        q_name = []
        _idx = 0
        while packet[_idx] > 0:
            _idx += 1
            print(_idx, packet[_idx: packet[_idx-1]+_idx])
            q_name.append(packet[_idx: packet[_idx-1]+_idx])
            _idx += packet[_idx-1]
        return q_name

    @staticmethod
    def get_txt_record(packet: bytes)->bytes:
        '''
        传入DNS数据包，解析TXT记录
        Header 12 byte
        Question Qname + Qtype(2 byte) + Qclass (2 byte)
        '''
        assert isinstance(packet, bytes)
        q_name = []
        _idx = 12
        while packet[_idx] > 0:
            _idx += 1
            q_name.append(packet[_idx: packet[_idx-1]+_idx])
            _idx += packet[_idx-1]
        _q_type, _q_class = struct.unpack('>HH', packet[_idx+1: _idx+5])
        answer = packet[_idx+5:]
        _r_name = packet[:2]
        if len(packet) < 10:
            # TODO: 基于包结构验证
            return b''
        _r_type, _r_class, _r_ttl, _r_dlength = struct.unpack('>HHIH', answer[2: 12])
        rdata = answer[12:]
        # print(r_type, r_class, r_ttl, r_dlength)
        return rdata[1:rdata[0]+1]
