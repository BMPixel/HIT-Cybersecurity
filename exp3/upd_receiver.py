import socket

TARGET_IP = '127.0.0.1'  # 请确保此IP地址与C代码中的目标服务器IP地址一致
TARGET_PORT = 9000          # 请确保此端口与C代码中的目标服务器端口一致

# 创建一个UDP套接字
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# 绑定套接字到目标IP和端口
sock.bind((TARGET_IP, TARGET_PORT))

print(f"正在监听 {TARGET_IP}:{TARGET_PORT}...")

while True:
    data, addr = sock.recvfrom(1024)  # 设置缓冲区大小为1024字节
    print(f"接收到数据包来自 {addr}: {data.decode()}")

    if data.decode() == 'Hello world':
        print("验证成功！")
        break

sock.close()
