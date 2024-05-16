import hashlib
from Block import Block
from datetime import datetime
import json


class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 5 

    def create_genesis_block(self):
        date = datetime(2023, 1, 1, 0, 0, 0)
        genesis_hash = self.calculate_hash(0, None, date, None, None)
        return Block(0, genesis_hash, None, date, None, None)
    
    def calculate_hash(self, index, previous_hash, timestamp, data, nonce):
        sha = hashlib.sha256()
        sha.update(f"{index}{previous_hash}{timestamp}{data}{nonce}".encode())
        return sha.hexdigest()
    
    def hash_matches_difficulty(self, hash_value):
        return hash_value.startswith('0' * self.difficulty)

    def is_valid_new_block(self, new_block, previous_block):
        if previous_block.index + 1 != new_block.index:
            print('invalid index')
            return False
        elif previous_block.hash != new_block.previous_hash:
            print('invalid previoushash')
            return False
        elif not self.hash_matches_difficulty(new_block.hash):
            print('invalid number of 0 ')
            return False
        elif self.calculate_hash(new_block.index, new_block.previous_hash, new_block.timestamp, new_block.data, new_block.nonce) != new_block.hash:
            print(f'invalid hash: {self.calculate_hash(new_block.index, new_block.previous_hash, new_block.timestamp, new_block.data, new_block.nonce)} {new_block.hash}')
            return False
        return True
    
    def is_valid_genesis_block(self,block0):
        if block0.index != 0:
            return False
        elif block0.hash != self.calculate_hash(0,None,datetime(2023, 1, 1, 0, 0, 0),None,None):
            return False
        return True
    
    
    def is_valid_chain(self,blockchain_to_validate):
        
        self.is_valid_genesis_block(blockchain_to_validate.chain[0])
        
        for i in range(1, len(blockchain_to_validate.chain)):
            if not self.is_valid_new_block(blockchain_to_validate.chain[i], blockchain_to_validate.chain[i - 1]):
                return False
        return True
    
    def find_block(self,index, previous_hash, timestamp, data, check_function):
        nonce = 0
        while True:
            if check_function():
                break
            hash_value = self.calculate_hash(index, previous_hash, timestamp, data, nonce)
            if self.hash_matches_difficulty(hash_value):
                return Block(index, hash_value, previous_hash, timestamp, data,nonce)
            nonce += 1
    
    def generate_next_block(self, data, check_function):
        previous_block = self.chain[-1]
        new_index = previous_block.index + 1
        new_timestamp = datetime.now()
        new_block = self.find_block(new_index, previous_block.hash, new_timestamp, data, check_function)

        return new_block
    
    def replace_chain(self, new_blockchain):
        if self.is_valid_chain(new_blockchain) and len(new_blockchain.chain) > len(self.chain):
            self.chain = new_blockchain.chain
            return True
        return False
    
    def add_block(self, block):
        self.chain.append(block)

    def serialize(self):
        chain_data = []
        for block in self.chain:
            block_data = block.__dict__.copy()
            block_data['timestamp'] = block_data['timestamp'].isoformat()  # Przekształć datetime na string
            chain_data.append(block_data)
        return json.dumps({"chain": chain_data, "difficulty": self.difficulty})
    
    def deserialize(self,data):
        blockchain_data = json.loads(data)
        blockchain = Blockchain()
        blockchain.chain = [Block(**block_data) for block_data in blockchain_data["chain"]]
        for block in blockchain.chain:
            block.timestamp = datetime.fromisoformat(block.timestamp)  # Przekształć string na datetime
        blockchain.difficulty = blockchain_data["difficulty"]
        return blockchain

    def calculate_balance(self, address):
        balance = 0
        for block in self.chain:
            if block.data:
                for transaction_dict in block.data:
                    if 'recipient' in transaction_dict and transaction_dict['recipient'] == address:
                        balance += transaction_dict['amount']
                    if 'sender' in transaction_dict and transaction_dict['sender'] == address:
                        balance -= transaction_dict['amount']
        return balance
