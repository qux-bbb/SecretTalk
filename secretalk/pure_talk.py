# coding:utf8

import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

def bytes_to_hex_string(bs):
    return ''.join(['%02x' % b for b in bs])


class Conversation:
    backend = default_backend()
    iv = b'parasiteetisarap'
    cipher = None

    def encrypt_msg(self, msg):
        # padder = padding.PKCS7(128).padder()
        # padded_data = padder.update(msg)
        # padded_data += padder.finalize()
        padding_len = (16 - len(msg) % 16)%16
        if padding_len:
            msg += b' '*padding_len
        encryptor = self.cipher.encryptor()
        encrypted_msg = encryptor.update(msg) + encryptor.finalize()
        return encrypted_msg

    def decrypt_msg(self, msg):
        decryptor = self.cipher.decryptor()
        decrypted_msg = decryptor.update(msg) + decryptor.finalize()
        # unpadder = padding.PKCS7(128).unpadder()
        # decrypted_msg = unpadder.update(decrypted_msg)
        # decrypted_msg += unpadder.finalize()
        return decrypted_msg

    def loop(self):
        while True:
            try:
                choice = input('1. encrypt\n2. decrypt\nchoice: ')
                if choice not in ['1', '2']:
                    continue
                if choice == '1':
                    plaintext = input('plaintext: ')
                    msg = bytes_to_hex_string(self.encrypt_msg(plaintext.encode('utf8')))
                    print('msg:{}'.format(msg))
                    continue
                if choice == '2':
                    ciphertext = input('ciphertext: ')
                    if ciphertext.startswith('msg:'):
                        plaintext = self.decrypt_msg(bytes.fromhex(ciphertext[4:]))
                        print(plaintext.decode('utf8'))
                    else:
                        print('[!] unrecognized ciphertext format')
                        continue
            except (KeyboardInterrupt, EOFError):
                print('loop exit')
                break
    
    def prepare(self):
        print('secret key generating...')
        # # Generate some parameters. These can be reused.
        # parameters = dh.generate_parameters(generator=2, key_size=2048,
        #                                     backend=self.backend)
        parameters_bytes = open('parameters_bytes', 'rb').read()
        parameters = self.backend.load_der_parameters(parameters_bytes)
        # Generate a private key for use in the exchange.
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        public_key_bytes = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        msg = 'pk:{}'.format(bytes_to_hex_string(public_key_bytes))
        print(msg)

        while True:
            peer_public_key_msg = input('Please input peer_public_key msg: ').strip()
            if peer_public_key_msg.startswith('pk:'):
                peer_public_key_bytes = bytes.fromhex(peer_public_key_msg[3:])
                peer_public_key = load_der_public_key(peer_public_key_bytes, self.backend)
                break
            else:
                print('[!] peer_public_key msg must start with "pk:"')
                continue
            
        shared_key = private_key.exchange(peer_public_key)
        # Perform key derivation.
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=self.backend
        ).derive(shared_key)
        print('debug shared_key: {}'.format(shared_key))
        print('debug derived_key: {}'.format(derived_key))
        self.cipher = Cipher(algorithms.AES(derived_key), modes.CBC(self.iv), backend=self.backend)


def main():
    try:
        con = Conversation()
        con.prepare()
        con.loop()
    except (KeyboardInterrupt, EOFError):
        print('normal exit')


if __name__ == "__main__":
    main()