#!/usr/bin/env python3

import tkinter as tk

# 创建窗口对象
window = tk.Tk()

# 设置窗口大小
window.geometry("300x200")

# 创建标签控件
label = tk.Label(window, text="Hello, World!")

# 显示标签控件
label.pack()

# 进入消息循环
window.mainloop()
