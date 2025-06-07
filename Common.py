import struct


TYPE_SYN = 1
TYPE_ACK = 2
TYPE_REQUEST = 3

Header_size = struct.calcsize("!IIIIHHHHH")

class GBNState:
    def __init__(self, expected_seq, last_sndpkt):
        self.expected_seq = expected_seq
        self.last_sndpkt = last_sndpkt

def pack_packet(src_port, des_port, seq, ack_num, type, window, length, data_start, data_end, chunk):
    if isinstance(chunk, str):
        data = chunk.encode('ascii')
    elif isinstance(chunk, bytes):
        data = chunk
    else:
        data = b''
    Header_Format = "!IIIIHHHHH"  # 26 bytes
    header = struct.pack(Header_Format, src_port, des_port, seq, ack_num, type, window, length, data_start, data_end)
    return header + data

def unpack_packet(data):
    Header_Format = "!IIIIHHHHH"  # 26 bytes
    header_size = struct.calcsize(Header_Format)
    header = data[:header_size]
    src_port, des_port, seq, ack_num, type, window, length, x, y = struct.unpack(Header_Format, header)
    if length == 0:
        chunk = b''
    else:
        chunk = data[header_size:header_size + length]

    return {
        'src_port': src_port,
        'des_port': des_port,
        'seq': seq,
        'ack_num': ack_num,
        'type': type,
        'window': window,
        'length': length,
        'data_start': x,
        'data_end': y,
        'chunk': chunk
    }