import base64
import os

from cryptography.fernet import Fernet

from secretalk.base import BaseConversation


def test_base():
    base_conversation = BaseConversation()

    secret_key = os.urandom(32)
    base_conversation.fernet = Fernet(base64.urlsafe_b64encode(secret_key))
    data = b"Hello World"
    encrypted_data = base_conversation.encrypt(data)
    decrypted_data = base_conversation.decrypt(encrypted_data)
    assert decrypted_data == data
