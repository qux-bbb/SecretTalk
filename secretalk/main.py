# coding:utf8

import re
import time
from threading import Lock, Thread
from win32 import win32gui, win32api, win32clipboard
import win32con

message_re = r'(?P<name>.+?) (?P<date_time>\d{4}/\d{1,2}/\d{1,2} \d{2}:\d{2}:\d{2})\r\n(?P<content>.+)'

lock = Lock()

class Conversation:
    classname = ''
    titlename = ''
    history_messages = []
    history_messages_num = 0
    cur_hwnd = None
    con_hwnd = None

    def __init__(self, classname, titlename):
        self.cur_hwnd = win32gui.GetForegroundWindow()

        self.classname = classname
        self.titlename = titlename
        self.con_hwnd = win32gui.FindWindow(classname, titlename)
        if not self.con_hwnd:
            print('can not find window, exit.')
            exit(0)

    def send_message(self, message):
        lock.acquire()

        win32gui.ShowWindow(self.con_hwnd, win32con.SW_MAXIMIZE)
        win32gui.SetForegroundWindow(self.con_hwnd)

        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardText(message, win32con.CF_UNICODETEXT)
        win32clipboard.CloseClipboard()

        win32api.keybd_event(0x11, 0, 0, 0)  # ctrl
        win32api.keybd_event(0x56, 0, 0, 0)  # 'v'
        win32api.keybd_event(0x11, 0, win32con.KEYEVENTF_KEYUP, 0)  # 释放按键
        win32api.keybd_event(0x56, 0, win32con.KEYEVENTF_KEYUP, 0)  # 释放按键

        win32api.keybd_event(0x11, 0, 0, 0)  # ctrl
        win32api.keybd_event(0x0d, 0, 0, 0)  # enter
        win32api.keybd_event(0x11, 0, win32con.KEYEVENTF_KEYUP, 0)  # 释放按键
        win32api.keybd_event(0x0d, 0, win32con.KEYEVENTF_KEYUP, 0)  # 释放按键

        time.sleep(1)

        win32gui.SetForegroundWindow(self.cur_hwnd)

        lock.release()

    def receive_message(self):
        lock.acquire()

        # for this problem: https://bbs.csdn.net/topics/390973288?page=1
        win32api.keybd_event(0x11, 0, 0, 0)  # ctrl
        win32api.keybd_event(0x11, 0, win32con.KEYEVENTF_KEYUP, 0)  # 释放按键

        win32gui.ShowWindow(self.con_hwnd, win32con.SW_MAXIMIZE)
        win32gui.SetForegroundWindow(self.con_hwnd)

        x_mid = int(win32api.GetSystemMetrics(win32con.SM_CXSCREEN)/2)
        y_mid = int(win32api.GetSystemMetrics(win32con.SM_CYSCREEN)/2)
        win32api.SetCursorPos([x_mid, y_mid])

        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0, 0)  # left mouse button
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0)  # 释放按键

        win32api.keybd_event(0x11, 0, 0, 0)  # ctrl
        win32api.keybd_event(0x41, 0, 0, 0)  # 'a'
        win32api.keybd_event(0x11, 0, win32con.KEYEVENTF_KEYUP, 0)  # 释放按键
        win32api.keybd_event(0x41, 0, win32con.KEYEVENTF_KEYUP, 0)  # 释放按键

        win32api.keybd_event(0x11, 0, 0, 0)  # ctrl
        win32api.keybd_event(0x43, 0, 0, 0)  # 'c'
        win32api.keybd_event(0x11, 0, win32con.KEYEVENTF_KEYUP, 0)  # 释放按键
        win32api.keybd_event(0x43, 0, win32con.KEYEVENTF_KEYUP, 0)  # 释放按键

        time.sleep(1)

        win32clipboard.OpenClipboard()
        text = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
        win32clipboard.CloseClipboard()

        win32gui.SetForegroundWindow(self.cur_hwnd)

        time.sleep(1)

        lock.release()

        return text

    def loop(self):
        while True:
            try:
                message = input('> ')
                if message:
                    self.send_message(message)
                else:
                    received_text = self.receive_message()
                    received_messages = re.findall(message_re, received_text)
                    received_messages_num = len(received_messages)
                    if self.history_messages_num < received_messages_num:
                        print()
                        for i in range(self.history_messages_num, received_messages_num):
                            print('[*] {}'.format(received_messages[i]))
                        self.history_messages = received_messages
                        self.history_messages_num = received_messages_num
            except (KeyboardInterrupt, EOFError):
                print('loop exit')
                break


if __name__ == "__main__":
    try:
        conversation_name = input('Please input conversation name: ')
        con = Conversation('TXGuiFoundation', conversation_name)
        t = Thread(target=con.loop)
        t.start()
        t.join()
    except (KeyboardInterrupt, EOFError):
        print('normal exit')