import socket
import threading
import mysql.connector
import datetime
import base64
import os
import bisect
import funcs

MESSAGE = 0x01
PUBKEY_REQ = 0x02
PUBKEY_X = 0x03
KEY_X = 0x04
CON = 0x05

TX_START = bytes.fromhex("66 26 07 01")
TX_END = bytes.fromhex("31 41 59 26")

db = mysql.connector.connect(
    host="localhost",
    user=os.getenv('USER'),
    password=os.getenv('MYSQL_PWD')
)

cur = db.cursor()

client_list = []

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 8080)

server_sock.bind(server_address)

server_sock.listen(0xffff)

class handle_client:
    def __init__(self, con=None, ip=None):
        self.con = con
        self.ip = ip

        self.data = con.recv(0xffffffff)
        contents = parse_message(self.data[1:], CON)
        self.addr = contents[0]

        client_list.append({"ip" : self.ip, "addr": self.addr, "socket" : con})

        mysql_query = ("SELECT * FROM client_messages WHERE dest_addr = %s AND timestamp > %s")
        cur.execute(mysql_query, (self.addr, datetime.datetime.fromtimestamp(contents[1], datetime.timezone.utc)))
        while True:
            self.data = con.recv(0xffffffff)
            contents = parse_message(self.data[1:], MESSAGE)
            dest_addr = contents[0]
            for i in client_list:
                if i["addr"] == dest_addr:
                    i["socket"].sendall(self.data)
            
            cur.execute(mysql_query, self.addr)


if __name__ == '__main__':
    while True:
        new_con, new_ip = server_sock.accept()
        threading.Thread(target = handle_client, args = (new_con, new_ip))
