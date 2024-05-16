
class Block:
    def __init__(self, index, hash, previous_hash, timestamp, data, nonce):
        self.index = index
        self.hash = hash
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.nonce = nonce 