import threading
import socket
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import os
import json
from blockchain import Blockchain
from transaction import Transaction



class User_node:
    def __init__(self, host, port, host_mother, port_mother):
        self.host = host
        self.port = port
        self.host_mother = host_mother
        self.port_mother = port_mother
        #sprawdzenie czy dany folder istenieje
        if os.path.exists(f'wallets/{self.port}_wallet.txt'):
            #w przypadku istenienia folderu(węzła) pobierane jest od użytkownika hasło tak długo aż będzie poprawne, po wpisaniu poprawnego hasła klucz prywatny jest importowany z portfela 
            correct_password = False
            while not correct_password:
                try:
                    self.password = input("Podaj haslo:")
                    self.private_key, self.public_key = self.read_from_wallet(self.password)
                    correct_password = True
                except:
                    print("Błędne hasło")
        # w przypadku gdy nowy węzeł jest tworzony, generowane są klucze, a klucz prywatny jest zapisywany do portfela
        else:
            self.password = input("Utwórz haslo:")
            self.private_key, self.public_key = self.generate_keys()
            self.save_to_wallet(self.password)
        self.print_lock = threading.Lock()
        #threading.Thread(target=self.send_request).start()
        self.peers = {}
        self.blockchain = Blockchain()
        self.pending_transactions = []
        self.run() 
        self.bool_check = False
        self.stop_mining = False

     
    def generate_keys(self):
        key = RSA.generate(2048) 
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return private_key, public_key
    
    def get_key_from_password(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_key(self, key: str, password: str) -> bytes:
        salt = os.urandom(16)
        key = self.get_key_from_password(password, salt)
        cipher = Fernet(key)
        encrypted_key = cipher.encrypt(self.private_key.encode())
        return salt + encrypted_key

    def decrypt_key(self, encrypted_data: bytes, password: str) -> str:
        salt, encrypted_key = encrypted_data[:16], encrypted_data[16:]
        key = self.get_key_from_password(password, salt)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_key).decode()
    
    def save_to_wallet(self, password):
        encrypted_key = self.encrypt_key(self.private_key, password)
        with open(f'wallets/{self.port}_wallet.txt', 'wb') as f:
            f.write(encrypted_key)
        with open(f'wallets/{self.port}_public_key.txt', 'wb') as f:
            f.write(self.public_key.encode('utf-8'))

    def read_from_wallet(self,password):
        with open(f'wallets/{self.port}_wallet.txt', 'rb') as f:
            encrypted_key = f.read()
        private_key = self.decrypt_key(encrypted_key, password)
        with open(f'wallets/{self.port}_public_key.txt', 'rb') as f:
            public_key = f.read().decode('utf-8')
        return private_key, public_key
    
    def listen_for_connections(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((self.host, self.port))
        listener.listen(5)
        with self.print_lock:
            print(f"Nasłuchiwanie na {self.host}:{self.port}...")
        
        while True:
            client_socket, addr = listener.accept()
            with self.print_lock:
                print(f"Połączono z {addr}")
            threading.Thread(target=self.handle_peer, args=(client_socket,)).start()

    def send_message(self, target_host, target_port, message):
        #encrypted_aes_key, encrypted_data = self.hybrid_encrypt(target_public_key, message)
        signature = base64.b64encode(self.sign_message(self.private_key,message)).decode('utf-8')
        
        payload = {
            "signature": signature,
            "message": message
        }
        serialized_payload = json.dumps(payload)
        
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((target_host, target_port))
        client_socket.send(serialized_payload.encode('utf-8'))
        client_socket.close()


    def handle_peer(self, client_socket):
        serialized_payload = ""
        while True:
             chunk = client_socket.recv(1024).decode('utf-8')
             serialized_payload += chunk
             if not chunk:
                break  

        try:
            payload = json.loads(serialized_payload)
            signature = base64.b64decode(payload["signature"])
            message = payload["message"]
        except json.JSONDecodeError:
            print("Nie można zdeserializować wiadomości")

        message_from_json = json.loads(message)
        public_key_node = message_from_json["public_key"]
        host_node = message_from_json["host"]
        port_node = message_from_json["port"]
        body_node = message_from_json["body"]

        bool = self.verify_signature(public_key_node, message, signature)
        if bool:
            print("Zweryfikowany klucz jest prawidłowy")
            if body_node == "Prośba o dołączenie":
                peer_ip = f"{host_node}:{port_node}"
                self.send_contacts(host_node,port_node)
                self.send_blockchain_request(host_node,port_node)
                if peer_ip not in self.peers:
                    self.peers[peer_ip] = public_key_node
            if body_node == "Witaj, przesylam kilka kontakow":
                 peer_ip = f"{host_node}:{port_node}"
                 if peer_ip not in self.peers:
                    self.peers[peer_ip] = public_key_node
                 nodes = message_from_json["nodes"]
                 for ip, public_key in nodes.items():
                    if ip not in self.peers:
                        if ip not in self.peers:
                            self.peers[ip] = public_key  
            if body_node == "Przesyłam nowy blockchain": 
                received_blockchain = self.blockchain.deserialize(message_from_json["blockchain"])
                if self.blockchain.replace_chain(received_blockchain):
                    self.send_blockchain()
                    print("Zamieniono blockchain, ilość bloków: ", len(self.blockchain.chain))
                    self.bool_check = True
                    self.pending_transactions = []
            if body_node == "Przesyłam obowiązującą listę transakcji":
                new_pending_list = message_from_json["transaction_list"]
                if self.pending_transactions == new_pending_list:
                    print("Posiadam identyczną listę transakcji oczekujących.")
                else:
                    if self.calculate_balance_pending(public_key_node, new_pending_list) > self.blockchain.calculate_balance(public_key_node):
                        print("Wysyłający nie ma wystarczająćej ilości pieniędzy!!!")
                        return
                    else:
                        for i in new_pending_list:
                            transaction = Transaction(i["sender"], i["recipient"], i["amount"],i["signature"])
                            if self.verify_transaction(transaction.sender,transaction,transaction.signature):
                                print("Zweryfikowany podpis transakcji jest prawidłowy")
                            else:
                                print("Zweryfikowany podpis transakcji jest błędny")
                                return
                    self.pending_transactions = new_pending_list
                    self.send_transaction()
            if body_node == "Przesyłam otrzymaną listę transakcji":
                new_pending_list = message_from_json["transaction_list"]
                if self.pending_transactions == new_pending_list:
                    print("Posiadam identyczną listę transakcji oczekujących.")
                    return
                else:
                    for i in new_pending_list:
                            transaction = Transaction(i["sender"], i["recipient"], i["amount"],i["signature"])
                            if self.verify_transaction(transaction.sender,transaction,transaction.signature):
                                print("Zweryfikowany podpis transakcji jest prawidłowy")
                            else:
                                print("Zweryfikowany podpis transakcji jest błędny")
                                return
                    self.pending_transactions = new_pending_list
                    self.send_transaction()


        else:
            print("Zweryfikowany klucz jest błędny")
        client_socket.close()
    
    
    def sign_message(self, private_key_pem, message):
        key = RSA.import_key(private_key_pem)
        h = SHA256.new(message.encode())
        signature = pkcs1_15.new(key).sign(h)
        return signature
    
    def verify_signature(self, public_key_pem, message, signature):
        key = RSA.import_key(public_key_pem)
        h = SHA256.new(message.encode())
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True 
        except (ValueError, TypeError):
            return False  

    #utworzenie formatki oraz wysłanie wiadomości z danymi potrzebnymi do dołączenia do sieci    
    def send_request(self):
        message_data = {
        "host": self.host,
        "port": self.port,
        "public_key": self.public_key,
        "body": 'Prośba o dołączenie'
}
        message_json = json.dumps(message_data)
        threading.Thread(target=self.send_message, args=(self.host_mother, self.port_mother, message_json,)).start()


    def send_contacts(self, host_recipient, port_recipient):
        message_data = {
        "host": self.host,
        "port": self.port,
        "public_key": self.public_key,
        "body": 'Witaj, przesylam kilka kontakow',
        "nodes": self.peers
}
        message_json = json.dumps(message_data)
        threading.Thread(target=self.send_message, args=(host_recipient, port_recipient, message_json,)).start()
    
    def print_peers(self):
        if len(self.peers) == 0:
            print("Brak kontaków")
        else: 
            for ip, public_key in self.peers.items():
                print("ip: ",ip,"pkey: ",public_key)

    def cli(self):
        while True:
            print("Dostępne polecenia:")
            print("exit - Zakończ program.")
            print("request - Wyślij zapytanie o dołączenie do sieci.")
            print("kontakty - Wypisuje ip i klucze publiczne znanych węzłów")
            print("kop - Węzeł rozpoczyna kopanie ")
            print("balans - Węzeł podaje salda kont ")
            cmd = input(">")
            if cmd == "exit":
                break
            elif cmd == "request":
                self.send_request()
            elif cmd == "kontakty":
                self.print_peers()
            elif cmd == "kop":
                self.dig()
            elif cmd == "balans":
                self.balance()
            elif cmd == "pay":
                nr = input("Numer: ")
                try:
                    nr = int(nr)  
                except ValueError:
                    print("Numer musi być liczbą całkowitą.")
                    continue

                if nr < 1 or nr > len(self.peers):
                    print(f"Numer musi być między 1 a {len(self.peers)}.")
                    continue

                kwota = input("Ile? ")
                try:
                    kwota = int(kwota)  
                except ValueError:
                    print("Kwota musi być liczbą całkowitą.")
                    continue
                
                if kwota < 0 :
                    print(f"Kwota musi być liczbą dodatnią.")
                    continue

                self.send_new_transaction(nr, kwota)
            elif cmd == "start":
                mine_thread = threading.Thread(target=self.mine_block)  
                mine_thread.daemon = True  
                mine_thread.start()  
            elif cmd == "stop":
                self.stop_mining_thread() 
            elif cmd == "help":
                print("Dostępne polecenia:")
                print("exit - Zakończ program.")
                print("request - Wyślij zapytanie o dołączenie do sieci.")
                print("kontakty - Wypisuje ip i klucze publiczne znanych węzłów")
                print("kop - Węzeł rozpoczyna kopanie (1 blok)")
                print("balans - Węzeł podaje salda kont ")
                print("pay - wyslij transakcje")
                print("start - Węzeł rozpoczyna kopanie asynchroniczne")
                print("stop - Węzeł przestaje kopac")
            else:
                print("Nieznane polecenie. Wpisz 'help' aby uzyskać listę poleceń.")

    def run(self):
        listen = threading.Thread(target=self.listen_for_connections)
        listen.daemon = True
        listen.start()
        cli_thread = threading.Thread(target=self.cli)
        cli_thread.start()

    def dig(self):
        self.bool_check = False
        T = Transaction(None,self.public_key,1).to_dict()
        self.pending_transactions.insert(0,T)
        new_block = self.blockchain.generate_next_block(self.pending_transactions, self.check_function)
        new_block.hash = '00000sdvdfvfdvvsdvfddfdfvdfsv'
        #print(new_block.data)
        if self.bool_check == True:
            return 
        else:
            self.blockchain.add_block(new_block)
            print("Wykopano blok, ilość bloków: ", len(self.blockchain.chain))
            self.send_blockchain()
            self.pending_transactions = []
        
    def send_blockchain(self):
        message_data = {
        "host": self.host,
        "port": self.port,
        "public_key": self.public_key,
        "body": 'Przesyłam nowy blockchain',
        "blockchain": self.blockchain.serialize()
}
        message_json = json.dumps(message_data)
        for ip, public_key in self.peers.items():
                host, port = ip.split(':')
                port = int(port)
                threading.Thread(target=self.send_message, args=(host, port, message_json,)).start()
    
    def send_blockchain_request(self,host,port):
        message_data = {
        "host": self.host,
        "port": self.port,
        "public_key": self.public_key,
        "body": 'Przesyłam nowy blockchain',
        "blockchain": self.blockchain.serialize()
}
        message_json = json.dumps(message_data)
        threading.Thread(target=self.send_message, args=(host, port, message_json,)).start()
        
    def balance(self):
        if len(self.blockchain.chain) == 1:
            print("Istnieje jedynie pusty blok startowy")
        else:
            my_balance = self.blockchain.calculate_balance(self.public_key)
            print(self.public_key, " posiada: ", my_balance,"COIN")
            for ip, public_key in self.peers.items():
                balance = self.blockchain.calculate_balance(public_key)
                print(public_key," posiada: ", balance, "COIN")
    
    def create_transaction(self, recipient, amount):
        transaction = Transaction(self.public_key, recipient, amount)
        transaction.sign(self.private_key)
        transaction = transaction.to_dict1()
        self.pending_transactions.append(transaction)
    
    def send_new_transaction(self,number,how):  
        my_balance = self.blockchain.calculate_balance(self.public_key)
        recipient_public_key = None
        number = int(number)
        it = 1
        for ip, public_key in self.peers.items():
            if it == number:
                host, port = ip.split(':')
                port = int(port)
                recipient_public_key = public_key
                break
            else:
                it = it +1

        if recipient_public_key is None:
            print("Nie znaleziono odbiorcy.")
            return        

        pending = self.calculate_balance_pending(self.public_key, self.pending_transactions)
        if my_balance<how+pending:
            print("Brak wystarczającej liczby COIN!!!!")
            return
        how = int(how)
        self.create_transaction(recipient_public_key, how)

        message_data = {
        "host": self.host,
        "port": self.port,
        "public_key": self.public_key,
        "body": 'Przesyłam obowiązującą listę transakcji',
        "transaction_list": self.pending_transactions
        }
        message_json = json.dumps(message_data)
        threading.Thread(target=self.send_message, args=(host, port, message_json,)).start()

    def send_transaction(self):
        self.bool_check = True
        message_data = {
        "host": self.host,
        "port": self.port,
        "public_key": self.public_key,
        "body": 'Przesyłam otrzymaną listę transakcji',
        "transaction_list": self.pending_transactions
}
        message_json = json.dumps(message_data)
        for ip, public_key in self.peers.items():
                host, port = ip.split(':')
                port = int(port)
                threading.Thread(target=self.send_message, args=(host, port, message_json,)).start()
        
    def calculate_balance_pending(self, address, list):
        balance = 0
        if len(list)==0:
            return balance
        else:
            for i in list:
                if 'recipient' in i and i['recipient'] == address:
                    balance += i['amount']
                if 'sender' in i and i['sender'] == address:
                    balance -= i['amount']
        return balance
        
    def verify_transaction(self, public_key,transaction,sign):
        transaction_dict = transaction.to_dict()
        signature = base64.b64decode(sign)
        key = RSA.import_key(public_key)
        transaction_string = json.dumps(transaction_dict)
        h = SHA256.new(transaction_string.encode())
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True 
        except (ValueError, TypeError):
            return False  
    
    def check_function(self):
        return self.bool_check
        
    def stop_mining_thread(self):
        self.stop_mining = True
  
    def mine_block(self):
        self.stop_mining = False
        while not self.stop_mining:
            T = Transaction(None,self.public_key,1).to_dict()
            self.pending_transactions.insert(0,T)
            self.bool_check = False
            new_block = self.blockchain.generate_next_block(self.pending_transactions, self.check_function)
            if self.bool_check == True:
                self.pending_transactions = []
                continue
            else:
                self.pending_transactions = []
                self.blockchain.add_block(new_block)
                print("Wykopano blok, ilość bloków: ", len(self.blockchain.chain))
                self.send_blockchain()