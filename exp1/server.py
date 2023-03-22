#!/usr/bin/env python3

import socket
import os

# 服务端地址和端口
server_address = ("localhost", 9999)

# 创建服务端socket对象
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_
server_socket.bind(server_address)
server_socket.listen()

print("服务器已启动，等待客户端连接...")


# 获取文件
def get_file(client_socket, filename):
    # 检查服务器是否有该文件
    if not os.path.isfile(os.path.join("server_files", filename)):
        print("服务器没有该文件")
        return
    # 打开文件
    with open(os.path.join("server_files", filename), "rb") as f:
        # 发送文件内容
        client_socket.sendall(f.read())
        print("文件已发送到客户端")


# 列出所有文件
def list_files(client_socket):
    # 获取server_files目录下的所有文件名
    files = os.listdir("server_files")
    # 将文件列表转换成字符串
    data = "\n".join(files)
    # 发送文件列表
    client_socket.sendall(data.encode())


# 接收文件
def receive_file(client_socket, filename):
    # 打开本地文件
    with open(os.path.join("server_files", filename), "wb") as f:
        # 接收文件内容
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            f.write(data)
        print("文件已保存到server_files目录")


while True:
    # 等待客户端连接
    client_socket, client_address = server_socket.accept()
    print("客户端已连接：", client_address)

    # 等待客户端输入指令
    while True:
        data = client_socket.recv(1024).decode()
        if not data:
            break

        if data.startswith("get "):
            get_file(client_socket, data.split()[1])

        elif data == "list":
            list_files(client_socket)

        elif data.startswith("send "):
            receive_file(client_socket, data.split()[1])

        else:
            print("无效指令")

    client_socket.close()
