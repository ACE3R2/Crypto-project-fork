import socket
import math
from abc import ABC, abstractmethod


class SocketConnection(ABC):

    def __init__(self, host, port):
        # When sending a message, the first max_len_byte_len bytes encode the length of the message that is subsequently sent
        # So the length of the message cannot be longer than what can be encoded in max_len_byte_len bytes
        self.max_len_byte_len = 8
        # Server-client connection
        self.conn = None
        # Endianness of sent and received messages
        self.endianness = "big"
        # Set the connection between the server and client (differs depending on which it is)
        self._connect(host, port)


    # Sets the connection between the server and client
    @abstractmethod
    def _connect(self, host, port):
        pass
        
        
    def message_into_bytestring(self, message):
        message_len = math.ceil(math.log2(message)/8)
        message_bytes = message.to_bytes(message_len, self.endianness)
        return message_bytes
        

    def bytestring_into_message(self, message_bytes):
        return int.from_bytes(message_bytes, self.endianness)
    
    
    
    # Sends the message (an int) through the connection
    # Uses the protocol where the first max_len_byte_len bytes of each message contain the length of the remaining message
    # Returns -1 (or raises error) if not able to send message, and 0 if able
    def send_full_message(self, message):
        print(f"Sending the message {message}")
        if self.conn == None:
            print("Socket has not been initialized!")
            return -1
        if message == 0:
            message_bytes = message.to_bytes(1, self.endianness)
            self._send_partial_message(message_bytes)
            return 0
        
        message_len = math.ceil(math.log2(message)/8)
        message_len = max(message_len,8)
        message_bytes = message.to_bytes(message_len, self.endianness)
        # Amount that can be encoded in max_len_byte_len bytes
        max_len_send = 2**(8*self.max_len_byte_len) - 1
        for i in range(0,message_len,max_len_send):
            send_end = min(message_len - i, max_len_send)
            self._send_partial_message(message_bytes[i:i+send_end])
        return 0
            
            
    def _send_partial_message(self, message_bytes):
        message_len = len(message_bytes)
        message_len_bytes = message_len.to_bytes(self.max_len_byte_len, self.endianness)
        print(f"Sending ... {message_len_bytes + message_bytes}")
        #print(f"{self.bytestring_into_message(message_len_bytes + message_bytes)} as an integer")
        self.conn.sendall(message_len_bytes)
        self.conn.sendall(message_bytes)
    
    
    
    
    # Returns message sent from other side in connection, converted into an int
    # Assumes other side is also a SocketConnection, so it follows the protocol for interpreting the data
    # Returns -1 if the sending side of the connection has closed
    def receive_full_message(self):
        if self.conn == None:
            print("Socket has not been initialized!")
            return -1
    
        # First max_len_byte_len bytes give the length (in bytes) of the actual message
        length_data = b''
        while len(length_data) < self.max_len_byte_len:
            length_data_add = self.conn.recv(self.max_len_byte_len - len(length_data))
            if self._check_connection_closed(length_data_add):
                return -1
            length_data += length_data_add
        message_len = int.from_bytes(length_data, self.endianness)
        
        # Interprets the actual message
        message_data = b''
        while len(message_data) < message_len:
            recv_amt = min(message_len - len(message_data), 1024)
            message_data_add = self.conn.recv(recv_amt)
            if self._check_connection_closed(length_data_add):
                return -1
            message_data += message_data_add
            
        print(f"Received ... {length_data + message_data}")
        #print(f"{self.bytestring_into_message(length_data + message_data)} as an integer")
        # Returns the message as an int rather than a collection of bytes/bits
        full_message = int.from_bytes(message_data, self.endianness)
        print(f"Received the message {full_message}")
        return full_message
        
    
    def _check_connection_closed(self, recvd_message):
        if not recvd_message:
            self._socket_closed_behavior()
            return True
        else:
            return False
    
    def _socket_closed_behavior(self):
        return

    def close_connection(self):
        self.conn.close()
