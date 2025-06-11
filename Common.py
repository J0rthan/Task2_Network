import struct


TYPE_SYN = 1
TYPE_ACK = 2
TYPE_REQUEST = 3

Header_size = struct.calcsize("!IIIIHHHHHH")  # 28bytes

class GBNState:
    def __init__(self, expected_seq, last_sndpkt):
        self.expected_seq = expected_seq
        self.last_sndpkt = last_sndpkt

def pack_packet(src_port, des_port, seq, ack_num, type, window, length, data_start, data_end, checksum, chunk):
    if isinstance(chunk, str):
        data = chunk.encode('ascii')
    elif isinstance(chunk, bytes):
        data = chunk
    else:
        data = b''
    Header_Format = "!IIIIHHHHHH"  # 28 bytes
    header = struct.pack(Header_Format, src_port, des_port, seq, ack_num, type, window, length, data_start, data_end, checksum)
    return header + data

def unpack_packet(data):
    Header_Format = "!IIIIHHHHHH"  # 28 bytes
    header_size = struct.calcsize(Header_Format)
    header = data[:header_size]
    src_port, des_port, seq, ack_num, type, window, length, x, y, ch_sum = struct.unpack(Header_Format, header)
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
        'checksum': ch_sum,
        'chunk': chunk
    }


def calculate_checksum(data):
    """
    计算 16 位校验和
    参数:
        data: bytes 类型的数据
    返回:
        checksum: int，16位校验值
    """
    # 转为可修改的 bytearray
    mutable_data = bytearray(data)

    # 将 checksum 字段清零（第26和27字节）
    mutable_data[26] = 0
    mutable_data[27] = 0

    # 如果长度为奇数，补零
    if len(mutable_data) % 2 == 1:
        mutable_data.append(0)

    checksum = 0
    for i in range(0, len(mutable_data), 2):
        word = (mutable_data[i] << 8) + mutable_data[i + 1]
        checksum += word

    # 处理溢出
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # 取反
    checksum = ~checksum & 0xFFFF

    return checksum


def notcorrupt(pkt):
    checksum_pkt = unpack_packet(pkt)['checksum']  # 先取发过来的包的checksum, 再本地计算checksum与其比较
    checksum_local = calculate_checksum(pkt)

    if checksum_pkt == checksum_local:
        return True
    else:
        return False

def maybe_corrupt_packet(packet: bytes, corrupt_rate=0.1) -> bytes:
    import random
    if random.random() < corrupt_rate:
        # 损坏：随便改一个字节（比如 checksum 的高位）
        mutable = bytearray(packet)
        mutable[26] ^= 0xFF  # 改变 checksum 高位，模拟错误
        return bytes(mutable)
    return packet