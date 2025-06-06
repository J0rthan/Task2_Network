from Common import *
from socket import *
from queue import Queue
from collections import defaultdict

import threading
import random


def gbn_receiver(serverSocket, data, client_addr, state: GBNState):
    pkt = unpack_packet(data)
    print(f"server端收到数据 seq={pkt['seq'] - 2}，返回 ack={pkt['seq'] - 2}")

    if pkt['type'] == TYPE_REQUEST:
        if random.random() < 0.2:
            print(f"server端模拟丢弃了第{pkt['seq'] - 2}个包")
            return

        if pkt['seq'] - 2 == state.expected_seq:
            snd_pkt = pack_packet(
                src_port=8000,
                des_port=client_addr[1],
                seq=state.expected_seq,
                ack_num=state.expected_seq,
                type=TYPE_ACK,
                window=5,
                length=0,
                chunk=b''
            )
            serverSocket.sendto(snd_pkt, client_addr)
            state.expected_seq += 1
            state.last_sndpkt = snd_pkt
            print(unpack_packet(state.last_sndpkt))

        else:
            print(unpack_packet(state.last_sndpkt))
            serverSocket.sendto(state.last_sndpkt, client_addr)


def handle_client(serverSocket, client_addr, q: Queue):
    thread_name = threading.current_thread().name
    print(f"[{thread_name}] 来自 {client_addr} 的客户端消息处理线程启动")

    seq_server = 1
    ack_num_server = 1
    handshake_done = False

    # GBN
    state = GBNState(
        expected_seq=1,
        last_sndpkt=pack_packet(
            src_port=8000,
            des_port=client_addr[1],
            seq=0,
            ack_num=0,
            type=TYPE_ACK,
            window=5,
            length=0,
            chunk=b''
        )
    )

    while True:
        try:
            data, addr = q.get()
            packet = unpack_packet(data)

            if not handshake_done:
                # 第一个握手请求
                if packet['type'] == TYPE_SYN:
                   syn_ack = pack_packet(
                       src_port=packet['des_port'],
                       des_port=packet['src_port'],
                       seq=seq_server,
                       ack_num=packet['seq'] + 1,
                       type=TYPE_ACK,
                       window=5,
                       length=0,
                       chunk=b''
                   )
                   serverSocket.sendto(syn_ack, client_addr)
                   seq_server += 1  # seq_server 加1
                   ack_num_server = packet['seq'] + 1

                elif packet['type'] == TYPE_ACK and packet['seq'] == ack_num_server:
                    handshake_done = True
                    print("三次握手成功，连接已建立")
                else:
                    continue

            # 连接建立之后的传输
            else:
                gbn_receiver(serverSocket, data, addr, state)

        except Exception as e:
            print(e)
            return



def main():
    serverSocket = socket(AF_INET, SOCK_DGRAM)
    serverSocket.bind(('127.0.0.1', 8000))
    print("UDP Server 监听8000端口")
    client_queues = defaultdict(Queue)  # 每个 client 一个 消息队列

    while True:
        data, client_addr = serverSocket.recvfrom(1024)  # 收客户端发过来的数据和地址
        if client_addr not in client_queues:
            print(f"收到来自{client_addr}的SYN，启动新的消息接受进程")
            thread = threading.Thread(
                target=handle_client,
                args=(serverSocket, client_addr, client_queues[client_addr]),
                name=f"Thread-{client_addr}"
            )
            thread.start()

        # 分发包
        client_queues[client_addr].put((data, client_addr))


if __name__ == '__main__':
    main()