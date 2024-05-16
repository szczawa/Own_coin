from user_node import User_node




if __name__ == "__main__":


    #węzeł użytkownik
    host = '127.0.0.1'
    port = 11111
    recipient_host = '127.0.0.1'
    recipient_port = 11112
    new_node = User_node(host, port, recipient_host, recipient_port)