from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
import json
import base64


class Transaction:
    def __init__(self, sender, recipient, amount, signature=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature

    def to_dict(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount
        }
    
    
    def to_dict1(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "signature": base64.b64encode(self.signature).decode('utf-8')
        }
        
    def sign(self, private_key):
        key = RSA.import_key(private_key)
        transaction_dict = self.to_dict()
        transaction_string = json.dumps(transaction_dict)
        h = SHA256.new(transaction_string.encode())
        signer = pkcs1_15.new(key)
        self.signature = signer.sign(h)

