# coding:utf8

import os
import base64
import binascii
import getpass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet

from base import BaseConversation, get_choice, base_dir


class Conversation(BaseConversation):

    my_friend_public_key = None
    my_private_key = None

    def loop(self):
        while True:
            try:
                choice = get_choice(
                    hint='1. encrypt\n2. decrypt\nchoice: ',
                    options=['1', '2']
                )
                if choice == '1':
                    secret_key = os.urandom(32)
                    self.fernet = Fernet(base64.urlsafe_b64encode(secret_key))
                    encrypted_secret_key = self.my_friend_public_key.encrypt(
                        secret_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    encrypted_secret_key_hex = binascii.hexlify(encrypted_secret_key)
                    raw_file_path = input('raw_file_path: ')
                    raw_file = open(raw_file_path, 'rb')
                    raw_content = raw_file.read()
                    raw_file.close()
                    encrypted_content = self.encrypt(raw_content)
                    encrypted_file_path = raw_file_path+'.encrypted'
                    encrypted_file = open(encrypted_file_path, 'wb')
                    encrypted_file.write(encrypted_secret_key_hex)
                    encrypted_file.write(b':')
                    encrypted_file.write(encrypted_content)
                    encrypted_file.close()
                    print('encrypted_file_path:{}'.format(encrypted_file_path))
                    continue
                if choice == '2':
                    encrypted_file_path = input('encrypted_file_path: ')
                    if encrypted_file_path.endswith('.encrypted'):
                        encrypted_file = open(encrypted_file_path, 'rb')
                        encrypted_secret_key_hex, encrypted_content = encrypted_file.read().split(b':', maxsplit=1)
                        encrypted_file.close()
                        encrypted_secret_key = binascii.unhexlify(encrypted_secret_key_hex)
                        secret_key = self.my_private_key.decrypt(
                            encrypted_secret_key,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )

                        self.fernet = Fernet(base64.urlsafe_b64encode(secret_key))
                        raw_content = self.decrypt(encrypted_content)
                        decrypted_file_path = encrypted_file_path[:-10]
                        decrypted_file = open(decrypted_file_path, 'wb')
                        decrypted_file.write(raw_content)
                        decrypted_file.close()
                        print('decrypted_file_path:{}'.format(decrypted_file_path))
                    else:
                        print('[!] unrecognized encrypted_file_path format. It need to be endswith ".encrypted"')
                        continue
            except (KeyboardInterrupt, EOFError):
                print('loop exit')
                break
    
    def prepare(self):
        my_key_dir = os.path.join(base_dir, 'private')
        my_private_key_file_path = os.path.join(my_key_dir, 'my_pri_key')
        my_public_key_file_path = os.path.join(my_key_dir, 'my_pub_key')
        friend_keys_dir_path = os.path.join(base_dir, 'friends')
        if not os.path.exists(my_key_dir):
            os.makedirs(my_key_dir)
        if not os.path.exists(friend_keys_dir_path):
            os.makedirs(friend_keys_dir_path)
        if not os.path.exists(my_private_key_file_path) or not os.path.exists(my_public_key_file_path):
            print('private or public key does not exist!')
            choice = get_choice(
                hint='1. generate key pair\n2. exit\nchoice: ',
                options=['1', '2']
            )
            if choice == '1':
                my_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=self.backend
                )
                private_key_password = getpass.getpass('input a password for private_key, default is empty: ')
                if private_key_password:
                    my_private_key_bytes = my_private_key.private_bytes(
                        serialization.Encoding.DER, 
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.BestAvailableEncryption(private_key_password.encode('utf8')))
                else:
                    my_private_key_bytes = my_private_key.private_bytes(
                        serialization.Encoding.DER, 
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption())
                open(my_private_key_file_path, 'wb').write(my_private_key_bytes)

                my_public_key = my_private_key.public_key()
                my_public_key_bytes = my_public_key.public_bytes(
                    serialization.Encoding.DER, 
                    serialization.PublicFormat.SubjectPublicKeyInfo)
                open(my_public_key_file_path, 'wb').write(my_public_key_bytes)
                print('key pair generated.')
            if choice == '2':
                exit(0)

        friend_key_names = os.listdir(friend_keys_dir_path)
        if not friend_key_names:
            print('there is no one friend\'s public key, and you can add it to friends folder, exit')
            exit(0)
        hint = 'friend_key_names:\n {}\ninput a key name you want: '.format(' \n'.join(friend_key_names))
        selected_friend_key_name = get_choice(
            hint=hint,
            options=friend_key_names
        )
        my_friend_public_key_file_path = os.path.join(friend_keys_dir_path, selected_friend_key_name)
        my_friend_public_key_content = open(my_friend_public_key_file_path, 'rb').read()
        self.my_friend_public_key = serialization.load_der_public_key(
            my_friend_public_key_content, 
            self.backend
        )

        my_private_key_content = open(my_private_key_file_path, 'rb').read()
        private_key_password = getpass.getpass('input the password of private_key, default is empty: ')
        if private_key_password:
            self.my_private_key = serialization.load_der_private_key(
                my_private_key_content, 
                private_key_password.encode('utf8'), 
                self.backend
            )
        else:
            self.my_private_key = serialization.load_der_private_key(
                my_private_key_content, 
                None, 
                self.backend
            )


def main():
    try:
        con = Conversation()
        con.prepare()
        con.loop()
    except (KeyboardInterrupt, EOFError):
        print('normal exit')
