# coding:utf8

import re
import time
import base64
import binascii

from threading import Lock
from win32 import win32gui, win32api, win32clipboard
import win32con

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
from cryptography.fernet import Fernet

from base import BaseConversation, is_hex_str


class Conversation(BaseConversation):
    msg_re = r'(?P<name>.+?) (?P<date_time>\d{4}/\d{1,2}/\d{1,2} \d{2}:\d{2}:\d{2})\r\n(?P<content>.+)'
    sender_name = ''
    classname = ''
    titlename = ''
    history_msgs_num = 0
    cur_hwnd = None
    con_hwnd = None
    lock = None

    def __init__(self, sender_name, classname, titlename):
        self.cur_hwnd = win32gui.GetForegroundWindow()

        self.sender_name = sender_name
        self.classname = classname
        self.titlename = titlename
        self.con_hwnd = win32gui.FindWindow(classname, titlename)
        if not self.con_hwnd:
            print('can not find window, exit.')
            exit(0)
        self.lock = Lock()

    def send_msg(self, msg):
        self.lock.acquire()

        # for this problem: https://bbs.csdn.net/topics/390973288?page=1
        win32api.keybd_event(0x11, 0, 0, 0)  # ctrl
        win32api.keybd_event(0x11, 0, win32con.KEYEVENTF_KEYUP, 0)  # release key

        win32gui.ShowWindow(self.con_hwnd, win32con.SW_MAXIMIZE)
        win32gui.SetForegroundWindow(self.con_hwnd)

        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardText(msg, win32con.CF_UNICODETEXT)
        win32clipboard.CloseClipboard()

        win32api.keybd_event(0x11, 0, 0, 0)  # ctrl
        win32api.keybd_event(0x56, 0, 0, 0)  # 'v'
        win32api.keybd_event(0x11, 0, win32con.KEYEVENTF_KEYUP, 0)  # release key
        win32api.keybd_event(0x56, 0, win32con.KEYEVENTF_KEYUP, 0)  # release key

        win32api.keybd_event(0x11, 0, 0, 0)  # ctrl
        win32api.keybd_event(0x0d, 0, 0, 0)  # enter
        win32api.keybd_event(0x11, 0, win32con.KEYEVENTF_KEYUP, 0)  # release key
        win32api.keybd_event(0x0d, 0, win32con.KEYEVENTF_KEYUP, 0)  # release key

        time.sleep(1)

        win32gui.SetForegroundWindow(self.cur_hwnd)

        self.lock.release()

    def receive_msg(self):
        self.lock.acquire()

        # for this problem: https://bbs.csdn.net/topics/390973288?page=1
        win32api.keybd_event(0x11, 0, 0, 0)  # ctrl
        win32api.keybd_event(0x11, 0, win32con.KEYEVENTF_KEYUP, 0)  # release key

        win32gui.ShowWindow(self.con_hwnd, win32con.SW_MAXIMIZE)
        win32gui.SetForegroundWindow(self.con_hwnd)

        time.sleep(1)

        x_mid = int(win32api.GetSystemMetrics(win32con.SM_CXSCREEN) / 2)
        y_mid = int(win32api.GetSystemMetrics(win32con.SM_CYSCREEN) / 2)
        win32api.SetCursorPos([x_mid, y_mid])

        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0, 0)  # left mouse button
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0)  # release key

        win32api.keybd_event(0x11, 0, 0, 0)  # ctrl
        win32api.keybd_event(0x41, 0, 0, 0)  # 'a'
        win32api.keybd_event(0x11, 0, win32con.KEYEVENTF_KEYUP, 0)  # release key
        win32api.keybd_event(0x41, 0, win32con.KEYEVENTF_KEYUP, 0)  # release key

        win32api.keybd_event(0x11, 0, 0, 0)  # ctrl
        win32api.keybd_event(0x43, 0, 0, 0)  # 'c'
        win32api.keybd_event(0x11, 0, win32con.KEYEVENTF_KEYUP, 0)  # release key
        win32api.keybd_event(0x43, 0, win32con.KEYEVENTF_KEYUP, 0)  # release key

        time.sleep(1)

        win32clipboard.OpenClipboard()
        text = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
        win32clipboard.CloseClipboard()

        win32gui.SetForegroundWindow(self.cur_hwnd)

        time.sleep(1)

        self.lock.release()

        return text

    def loop(self):
        while True:
            try:
                msg = input('> ')
                if msg:
                    encrypted_text = self.encrypt(msg.encode('utf8'))
                    msg = binascii.hexlify(encrypted_text).decode('utf8')
                    final_msg = 'msg:{}'.format(msg)
                    self.send_msg(final_msg)
                else:
                    received_text = self.receive_msg()
                    received_msgs = re.findall(self.msg_re, received_text)
                    received_msgs_num = len(received_msgs)
                    if self.history_msgs_num < received_msgs_num:
                        print()
                        for i in range(self.history_msgs_num, received_msgs_num):
                            if received_msgs[i][0] != self.sender_name and received_msgs[i][2].startswith('msg:') \
                                    and is_hex_str(received_msgs[i][2][4:]):
                                received_bytes = bytes.fromhex(received_msgs[i][2][4:])
                                try:
                                    decrypted_bytes = self.decrypt(received_bytes)
                                    print('[*] {}'.format(decrypted_bytes.decode('utf8')))
                                except Exception as e:
                                    print('[!] decrypt failed: {}'.format(e.message))
                        self.history_msgs_num = received_msgs_num
            except (KeyboardInterrupt, EOFError):
                print('loop exit')
                break

    def prepare(self):
        # Generate a private key for use in the exchange.
        private_key = ec.generate_private_key(ec.SECP384R1(), self.backend)
        public_key = private_key.public_key()

        public_key_bytes = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        msg = 'pk:{}'.format(binascii.hexlify(public_key_bytes).decode('utf8'))
        self.send_msg(msg)

        print('wait for peer_public_key...')
        while True:
            received_text = self.receive_msg()
            received_msgs = re.findall(self.msg_re, received_text)
            filted_msgs = []
            for received_msg in received_msgs:
                if received_msg[0] != self.sender_name and received_msg[2].startswith('pk:'):
                    filted_msgs.append(received_msg)
            if filted_msgs:
                content = filted_msgs[-1][2]
                if is_hex_str(content[3:]):
                    peer_public_key_bytes = bytes.fromhex(content[3:])
                    peer_public_key = load_der_public_key(peer_public_key_bytes, self.backend)
                    break
                else:
                    print('[!] incorrect hex_str')
            time.sleep(5)

        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        # Perform key derivation.
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=self.backend
        ).derive(shared_key)
        secret_key = base64.urlsafe_b64encode(derived_key)
        self.fernet = Fernet(secret_key)


def main():
    try:
        sender_name = input('Please enter your nickname in QQ: ')
        conversation_name = input('Please enter the conversation name or your friend\'s nickname: ')
        con = Conversation(sender_name, 'TXGuiFoundation', conversation_name)
        con.prepare()
        con.loop()
    except (KeyboardInterrupt, EOFError):
        print('normal exit')
