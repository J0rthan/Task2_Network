import time
import threading
import sys
import pandas as pd
import math
import random

from Common import *
from socket import *


def gbn_sender(client, server_addr, start_seq, ack_base_seq):
    def start_timer():
        nonlocal timer_start
        timer_start = time.time()

    def stop_timer():
        nonlocal timer_start
        timer_start = None

    def is_timeout():
        return timer_start and time.time() - timer_start >= 0.3  # 0.3 * 1000 = 300ms

    def resend_packets():
        nonlocal total_send
        for i in range(base, next_seq):
            pkt = unpack_packet(unacked_packets[i])
            data = pkt['chunk']
            chunk_start = pkt['data_start']
            chunk_end = pkt['data_end']
            pkt = pack_packet(
                src_port=client.getsockname()[1],
                des_port=server_addr[1],
                seq=start_seq + i,
                ack_num=ack_base_seq,
                type=TYPE_REQUEST,
                window=window_byte_limit,
                length=len(data),
                data_start=chunk_start,
                data_end=chunk_end,
                chunk=data
            )
            client.sendto(pkt, server_addr)
            total_send += 1
            print(f"重传第{i}个数据报(从第{chunk_start} ~ {chunk_end} 个字节)")

    def recv_ack_loop():
        nonlocal base
        nonlocal RTT_list
        while base < 31:
            try:
                data, _ = client.recvfrom(1024)
                ack_pkt = unpack_packet(data)
                if ack_pkt['type'] == TYPE_ACK:
                    ack_num = ack_pkt['ack_num']
                    elapsed_time = (time.time() - timer_start) * 1000
                    RTT_list.append(elapsed_time)
                    print(f"第{ack_num}个数据报server端已收到(从第 {ack_pkt['data_start']} ~ {ack_pkt['data_end']} 个字节)，RTT是{elapsed_time:.4f}ms")
                    with lock:
                        base = ack_num + 1

                        for seq in list(unacked_packets.keys()):
                            if seq <= ack_num:
                                del unacked_packets[seq]

                        if base == next_seq:
                            stop_timer()
                        elif timer_start is None:
                            start_timer()
            except Exception as e:
                print("[ERROR] 接收线程出错：", e)

    def timer_loop():
        while base < 31:
            with lock:
                if is_timeout():
                    start_timer()
                    print("计时器触发超时")
                    resend_packets()

    def total_window_bytes(unacked_packets):
        return sum(len(pkt) for pkt in unacked_packets.values())

    base = 1
    next_seq = 1
    timer_start = None
    lock = threading.Lock()
    total_send = 0
    RTT_list = []
    window_byte_limit = 400
    x = 0  # data_start
    y = 0  # data_end
    unacked_packets = {}

    # 启动接受进程
    threading.Thread(target=recv_ack_loop, daemon=True).start()
    # 启动计时器进程
    threading.Thread(target=timer_loop, daemon=True).start()

    while base < 31:
        with lock:
            while next_seq < 31 and total_window_bytes(unacked_packets) < window_byte_limit:
                if base == next_seq:
                    start_timer()

                pkt_len = random.randint(14, 54)  # header = 26 bytes
                if total_window_bytes(unacked_packets) + pkt_len > window_byte_limit:
                    break

                data = b'A' * (pkt_len)

                if y == 0:
                    x = y
                else:
                    x = y + 1
                y = x + pkt_len + Header_size - 1

                pkt = pack_packet(
                    src_port=client.getsockname()[1],
                    des_port=server_addr[1],
                    seq=start_seq + next_seq,
                    ack_num=ack_base_seq,
                    type=TYPE_REQUEST,
                    window=window_byte_limit,
                    length=len(data),
                    data_start=x,
                    data_end=y,
                    chunk=data
                )

                client.sendto(pkt, server_addr)
                print(f"第{next_seq}个数据报(从第{x} ~ {y} 个字节)已发送")
                unacked_packets[next_seq] = pkt
                total_send += 1
                next_seq += 1
                ack_base_seq += 1

    return total_send, RTT_list


def Estimated_RTT(RTT_list):
    alpha = 0.125

    RTT_series = pd.Series(RTT_list)

    estimated_RTT = RTT_series.iloc[0]
    estimated_RTT_list = [estimated_RTT]

    for sample_RTT in RTT_series.iloc[1:]:
        estimated_RTT = (1 - alpha) * estimated_RTT + alpha * sample_RTT
        estimated_RTT_list.append(estimated_RTT)

    estimated_RTT_series = pd.Series(estimated_RTT_list)

    return estimated_RTT_series.iloc[-1]


def Dev_RTT(RTT_list, Estimated_RTT):
    beta = 0.25

    RTT_series = pd.Series(RTT_list)

    Dev_RTT = 0
    Dev_RTT_list = [Dev_RTT]

    for sample_RTT in RTT_series.iloc:
        Dev_RTT = (1 - beta) * Dev_RTT + beta * abs(sample_RTT - Estimated_RTT)
        Dev_RTT_list.append(Dev_RTT)

    Dev_RTT_series = pd.Series(Dev_RTT_list)

    return Dev_RTT_series.iloc[-1]


def main():
    client = socket(AF_INET, SOCK_DGRAM)
    serverIP = sys.argv[1]
    serverPort = int(sys.argv[2])
    server_addr = (serverIP, serverPort)

    seq_num = 1
    ack_num = 1
    window = 400

    # 发送 SYN
    handshake_mes = pack_packet(
        src_port=client.getsockname()[1],
        des_port=serverPort,
        seq=seq_num,
        ack_num=ack_num,
        type=TYPE_SYN,
        window=window,
        length=0,
        data_start=0,
        data_end=0,
        chunk=b''
    )
    client.sendto(handshake_mes, server_addr)
    print("发送 SYN")

    # 接收 ACK
    data, addr = client.recvfrom(1024)
    ack_msg = unpack_packet(data)
    print(ack_msg)

    if ack_msg['type'] == TYPE_ACK and ack_msg['ack_num'] == seq_num + 1:
        print("收到 ACK，发送最后的 ACK 确认")

        seq_num += 1
        ack_num = ack_msg['seq'] + 1

        final_ack = pack_packet(
            src_port=client.getsockname()[1],
            des_port=serverPort,
            seq=seq_num,
            ack_num=ack_num,
            type=TYPE_ACK,
            window=window,
            length=0,
            data_start=0,
            data_end=0,
            chunk=b''
        )
        client.sendto(final_ack, server_addr)
        print("连接建立成功")

        # start GBN
        total_send, RTT_list = gbn_sender(client, addr, seq_num, ack_num)

        loss_rate = (1 - 30.0 / total_send) * 100
        Est_RTT = Estimated_RTT(RTT_list)
        D_RTT = Dev_RTT(RTT_list, Est_RTT)
        print(f"丢包率：{loss_rate:.4f}%")
        print(f"最大RTT={max(RTT_list):.4f}ms")
        print(f"最小RTT={min(RTT_list):.4f}ms")
        print(f"平均RTT={Est_RTT:.4f}ms")
        print(f"RTT的标准差={D_RTT:.4f}ms")


if __name__ == "__main__":
    main()