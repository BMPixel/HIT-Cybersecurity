import tkinter as tk
from tkinter import ttk
import re
import socket
import threading
import concurrent.futures
import time
import ipaddress


def scan_port_and_write(ip_address, port):
    """扫描端口并将结果写入结果列表"""
    result = "TODO"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            result = "OPEN"
        else:
            result = "CLOSE"
        sock.close()
    except socket.gaierror:
        result = "ERROR"
    except socket.error:
        result = "ERROR"

    print(f"{ip_address}:{port} {result}")

    return (ip_address, port, result)


class PortScanner:
    def __init__(self, master):
        self.master = master
        self.master.title("端口扫描程序")
        self.lock = threading.Lock()

        # 起始IP地址
        self.start_ip_label = ttk.Label(master, text="起始IP地址:")
        self.start_ip_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        self.start_ip_entry = ttk.Entry(master, width=20)
        self.start_ip_entry.insert(0, "120.53.10.6")
        self.start_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        # 结束IP地址
        self.end_ip_label = ttk.Label(master, text="结束IP地址:")
        self.end_ip_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

        self.end_ip_entry = ttk.Entry(master, width=20)
        self.end_ip_entry.insert(0, "120.53.10.7")
        self.end_ip_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        # 目标端口范围
        self.port_range_label = ttk.Label(master, text="目标端口范围:")
        self.port_range_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)

        self.start_label = ttk.Label(master, text="起始端口:")
        self.start_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)

        self.start_entry = ttk.Entry(master, width=10)
        self.start_entry.insert(0, "8800")
        self.start_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)

        self.end_label = ttk.Label(master, text="结束端口:")
        self.end_label.grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)

        self.end_entry = ttk.Entry(master, width=10)
        self.end_entry.insert(0, "9000")
        self.end_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)

        self.thread_label = ttk.Label(master, text="线程数:")
        self.thread_label.grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)

        self.thread_entry = ttk.Entry(master, width=10)
        self.thread_entry.insert(0, "100")
        self.thread_entry.grid(row=5, column=1, padx=5, pady=5, sticky=tk.W)

        self.scan_button = ttk.Button(master, text="开始扫描", command=self.scan_ports)
        self.scan_button.grid(row=6, column=0, columnspan=2, padx=5, pady=5)

        self.result_label = ttk.Label(master, text="扫描结果:")
        self.result_label.grid(row=7, column=0, padx=5, pady=5, sticky=tk.W)

        self.result_text = tk.Text(master, height=20, width=50)
        self.result_text.grid(row=8, column=0, columnspan=2, padx=5, pady=5)

        self.result_list = {}

    def scan_ports(self):
        """扫描端口"""
        start_ip = self.start_ip_entry.get()
        end_ip = self.end_ip_entry.get()
        start_port = int(self.start_entry.get())
        end_port = int(self.end_entry.get())
        worker_count = int(self.thread_entry.get())
        self.result_text.delete("1.0", tk.END)

        # check if the IP range is valid
        try:
            start_ip_obj = ipaddress.ip_address(start_ip)
            end_ip_obj = ipaddress.ip_address(end_ip)
        except ValueError:
            self.result_text.insert(tk.END, "IP地址无效，请重新输入！")
            return

        if end_ip_obj < start_ip_obj:
            self.result_text.insert(tk.END, "结束IP地址不能小于起始IP地址！")
            return

        # check if the port range is valid
        if (
            start_port < 0
            or start_port > 65535
            or end_port < 0
            or end_port > 65535
            or end_port < start_port
        ):
            self.result_text.insert(tk.END, "端口范围无效，请重新输入！")
            return

        # init the result list
        self.init_result_list(start_ip, end_ip, start_port, end_port)

        # start the scan
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=worker_count
        ) as executor:
            futures = []
            print("开始分配线程..")
            for ip in range(int(start_ip_obj), int(end_ip_obj) + 1):
                ip_address = str(ipaddress.ip_address(ip))
                for port in range(start_port, end_port + 1):
                    futures.append(
                        executor.submit(scan_port_and_write, ip_address, port)
                    )

                for future in concurrent.futures.as_completed(futures):
                    if future.result():
                        ip, port, status = future.result()
                        self.result_list[ip][port] = status

        print("扫描完成！")
        self.update_result_text()

    def is_valid_ip(self, ip_address):
        """检查IP地址是否有效"""
        pattern = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        return re.match(pattern, ip_address)

    def update_result_text(self):
        """更新结果文本框, 用于显示扫描结果"""

        def result_to_str(ip_address, start, end, result):
            if result == "OPEN":
                status_str = "开放"
            elif result == "CLOSE":
                status_str = "关闭"
            elif result == "ERROR":
                status_str = "错误"
            else:
                status_str = "未知"
            if start == end:
                return f"{ip_address} 端口{start}：{status_str}\n"
            else:
                return f"{ip_address} 端口{start}-{end}：{status_str}\n"

        self.result_text.delete("1.0", tk.END)
        list_to_show = []  # element in form of (ip_address, start, end, result)
        for ip_address, port_statuses in self.result_list.items():
            for port, status in enumerate(port_statuses):
                if status == "IGNORE":
                    continue
                if len(list_to_show) == 0:
                    list_to_show.append((ip_address, port, port, status))
                else:
                    if (
                        list_to_show[-1][0] == ip_address
                        and list_to_show[-1][3] == status
                    ):
                        list_to_show[-1] = (
                            list_to_show[-1][0],
                            list_to_show[-1][1],
                            port,
                            status,
                        )
                    else:
                        list_to_show.append((ip_address, port, port, status))

        for item in list_to_show:
            self.result_text.insert(tk.END, result_to_str(*item))

    def init_result_list(self, start_ip, end_ip, start_port, end_port):
        """初始化结果列表，将所有端口设置为未知状态"""
        self.result_list = {}
        with self.lock:
            start_ip_obj = ipaddress.ip_address(start_ip)
            end_ip_obj = ipaddress.ip_address(end_ip)
            for ip in range(int(start_ip_obj), int(end_ip_obj) + 1):
                ip_address = str(ipaddress.ip_address(ip))
                self.result_list[ip_address] = []
                for port in range(1, 65536):
                    if port > start_port and port <= end_port:
                        self.result_list[ip_address].append("UNKNOWN")
                    else:
                        self.result_list[ip_address].append("IGNORE")


if __name__ == "__main__":
    root = tk.Tk()
    port_scanner = PortScanner(root)
    root.mainloop()
