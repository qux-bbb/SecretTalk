# coding:utf8

import base64
import binascii

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
from cryptography.fernet import Fernet

from base import BaseConversation, get_choice, is_hex_str


class Conversation(BaseConversation):

    def loop(self):
        while True:
            try:
                choice = get_choice(
                    hint='1. encrypt\n2. decrypt\nchoice: ',
                    options=['1', '2']
                )
                if choice == '1':
                    plaintext = input('plaintext: ')
                    encrypted_text = self.encrypt(plaintext.encode('utf8'))
                    msg = binascii.hexlify(encrypted_text).decode('utf8')
                    print('encrypted:{}'.format(msg))
                    continue
                if choice == '2':
                    ciphertext = input('ciphertext: ')
                    if ciphertext.startswith('encrypted:') and is_hex_str(ciphertext[10:]):
                        try:
                            plaintext = self.decrypt(bytes.fromhex(ciphertext[10:]))
                            print('decrypted:{}'.format(plaintext.decode('utf8')))
                        except Exception as e:
                            print('[!] decrypt failed: {}'.format(e.message))
                    else:
                        print('[!] unrecognized ciphertext format')
                        continue
            except (KeyboardInterrupt, EOFError):
                print('loop exit')
                break

    def prepare(self):
        private_key = ec.generate_private_key(ec.SECP384R1(), self.backend)
        public_key = private_key.public_key()

        public_key_bytes = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        msg = 'peer_public_key:{}'.format(binascii.hexlify(public_key_bytes).decode('utf8'))
        print('Please send the following message to your friend')
        print(msg)

        peer_public_key = ''
        while True:
            peer_public_key_msg = input('Please input peer_public_key msg from your friend: ').strip()
            if peer_public_key_msg.startswith('peer_public_key:') and is_hex_str(peer_public_key_msg[16:]):
                peer_public_key_bytes = bytes.fromhex(peer_public_key_msg[16:])
                peer_public_key = load_der_public_key(peer_public_key_bytes, self.backend)
                break
            else:
                print('[!] peer_public_key msg must start with "peer_public_key:"')
                continue
            
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
        con = Conversation()
        con.prepare()
        con.loop()
    except (KeyboardInterrupt, EOFError):
        print('normal exit')
