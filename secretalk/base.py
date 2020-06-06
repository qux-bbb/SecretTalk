# coding:utf8

import os
import re

from cryptography.hazmat.backends import default_backend


base_dir = os.path.dirname(os.path.abspath(__file__))

def get_choice(hint, options):
    """
    获取用户选择的选项
    :param hint: 提示信息
    :param options: 可输入的合法选项
    :return: 用户输入的合法选项
    """
    while True:
        try:
            choice = input(hint)
            if choice in options:
                return choice
            else:
                print('[!] no-existent option')
        except KeyboardInterrupt:
            print('\n[*] KeyboardInterrupt exit')
            exit(0)


def is_hex_str(data):
    """
    判断是否为偶数长度的十六进制字符串
    :param data: hex str
    :return: bool
    """
    if re.match(r'([0-9a-f]{2})+$', data):
        return True
    else:
        return False


class BaseConversation:

    backend = default_backend()
    fernet = None
    
    def encrypt(self, data):
        """
        加密
        :param data: 待加密数据
        :return: 已加密数据
        """
        return self.fernet.encrypt(data)

    def decrypt(self, data):
        """
        解密
        :param data: 已加密数据
        :return: 已解密数据
        """
        return self.fernet.decrypt(data)

    def loop(self):
        """
        循环处理数据
        :return: None
        """
        pass

    def prepare(self):
        """
        准备必要信息
        :return: None
        """
        pass
