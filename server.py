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
    host=os.getenv('MYSQL_HOST'),
    user=os.getenv('MYSQL_USER'),
    password=os.getenv('MYSQL_PWD'),
    database=os.getenv('SEMAPHORE_DB_NAME')
)

cur = db.cursor()

client_list = []

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (socket.gethostbyname(socket.gethostname()), 6626)

server_sock.bind(server_address)

server_sock.listen(0xffff)

print("Server listening")

class handle_client:
    def __init__(self, con=None, ip=None):
        self.con = con
        self.ip = ip

        self.data = self.con.recv(0xffffff)
        contents = funcs.parse_message(self.data[1:], CON)
        self.addr = contents[0]

        print(f'{self.addr} connected')

        client_list.append({"ip" : self.ip, "addr": self.addr, "socket" : con})

        mysql_query = ("SELECT dest_addr, origin_addr, timestamp, sz, content, signature FROM messages WHERE dest_addr = %s AND timestamp > %s")
        cur.execute(mysql_query, (self.addr, datetime.datetime.fromtimestamp(int.from_bytes(contents[1], 'little'), datetime.timezone.utc)))

        for (dest_addr, origin_addr, timestamp, sz, content, signature) in cur:
            self.data = TX_START + bytes.fromhex(dest_addr) + bytes.fromhex(origin_addr) + (datetime.datetime.strptime(timestamp, datetime.timezone.utc)).timestamp() + int(sz).to_bytes(4, 'little') + base64.b64decode(content) + len(base64.b64decode(signature)) + base64.b64decode(signature) + TX_END
            self.con.sendall(self.data)

        while True:
            self.data = self.con.recv(0xffffff)
            contents = funcs.parse_message(self.data[1:], MESSAGE)
            destination_address = contents[0]
            for i in client_list:
                if i["addr"] == destination_address:
                    i["socket"].sendall(self.data)
                    break
            mysql_query = ("INSERT INTO messages(dest_addr, origin_addr, timestamp, sz, content, signature)"
                           "VALUES(%s, %s, %s, %s, %s, %s)")
            cur.execute(mysql_query, (self.addr, contents[1], contents[2], contents[3], contents[4], contents[6]))
            print((self.addr, contents[1], contents[2], contents[3], contents[4], contents[6]))


if __name__ == '__main__':
    while True:
        new_con, new_ip = server_sock.accept()
        print("New connection")
        thread = threading.Thread(target = handle_client, args = (new_con, new_ip))
        thread.start()
