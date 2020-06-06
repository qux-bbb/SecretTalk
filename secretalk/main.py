# coding:utf8

from base import get_choice
from online_mode import blink_qq, pure_talk_ec_share_key, pure_talk_rsa_share_key
from offline_mode import pure_talk, pure_file


def main():
    choice = get_choice(
        hint='1. online\n2. offline\nchoice: ',
        options=['1', '2']
    )
    if choice == '1':
        choice = get_choice(
            hint='1. blink_qq\n2. pure_talk_ec_share_key\n3. pure_talk_rsa_share_key\nchoice: ',
            options=['1', '2', '3']
        )
        if choice == '1':
            blink_qq.main()
        if choice == '2':
            pure_talk_ec_share_key.main()
        if choice == '3':
            pure_talk_rsa_share_key.main()
    if choice == '2':
        choice = get_choice(
            hint='1. pure_talk\n2. pure_file\nchoice: ',
            options=['1', '2']
        )
        if choice == '1':
            pure_talk.main()
        if choice == '2':
            pure_file.main()
            pass


if __name__ == "__main__":
    main()
