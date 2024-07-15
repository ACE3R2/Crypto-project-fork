import socket
from socketconnection import SocketConnection


class ServerSocketConnection(SocketConnection):


    # Listens at (host,port) for an incoming connection and connects with it
    def _connect(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host,port))
        s.listen()
        self.conn, addr = s.accept()
        print(f"Connected to client with address {addr}")
        
    
    def _socket_closed_behavior(self):
        print("Client socket is no longer running")
        self.close_connection()
        
		
		

class ClientSocketConnection(SocketConnection):


    # Connects with the server at (host, port)
    def _connect(self, host, port):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((host,port))
        print(f"Connected with the server at {host}:{port}")
        
    
    def _socket_closed_behavior(self):
        print("Server socket is no longer running")
        self.close_connection()
        
        