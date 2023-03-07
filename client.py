#!/usr/bin/env python3

import socket
import os

# 服务器地址和端口
server_address = ("localhost", 9999)

# 创建客户端socket对象
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(server_address)


# 获取文件
def get_file(filename):
    # 发送指令到服务器
    client_socket.sendall(("get " + filename).encode())
    # 接收文件内容
    data = client_socket.recv(1024)
    # 将文件写入本地
    with open(os.path.join("client_files", filename), "wb") as f:
        f.write(data)
        print("文件已保存到client_files目录")


# 列出所有文件
def list_files():
    # 发送指令到服务器
    client_socket.sendall("list".encode())
    # 接收文件列表
    data = client_socket.recv(1024)
    # 打印文件列表
    print(data.decode())


# 发送文件
def send_file(filename):
    # 检查本地是否有该文件
    if not os.path.isfile(os.path.join("client_files", filename)):
        print("本地没有该文件")
        return
    # 发送指令到服务器
    client_socket.sendall(("send " + filename).encode())
    # 打开本地文件
    with open(os.path.join("client_files", filename), "rb") as f:
        # 发送文件内容
        client_socket.sendall(f.read())
        print("文件已发送到服务器")


# 客户端等待用户输入指令
while True:
    user_input = input(
        """请输入指令:
    1. get filename
    2. list
    3. send filename
    4. exit
    """
    )

    if user_input.startswith("get "):
        get_file(user_input.split()[1])

    elif user_input == "list":
        list_files()

    elif user_input.startswith("send "):
        send_file(user_input.split()[1])

    elif user_input == "exit":
        client_socket.close()
        break
    else:
        print("无效指令")

# 关闭客户端socket对象
client_socket.close()
