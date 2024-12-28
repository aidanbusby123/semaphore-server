import socket
import threading
import sqlite3
import datetime
import base64
import funcs

MESSAGE = 0x01
PUBKEY_REQ = 0x02
PUBKEY_X = 0x03
KEY_X = 0x04
CON = 0x05

TX_START = bytes.fromhex("02 07 01 08")
TX_END = bytes.fromhex("03 01 04 01")

client_list = []

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (("", 6626))

server_sock.bind(server_address)

server_sock.listen(0xffff)

print("****SEMAPHORE SERVER****")

def init_db():
    db = sqlite3.connect("messages.db")
    cur = db.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS `messages` (
	`dest_addr` CHAR(32),
	`origin_addr` CHAR(32),
	`timestamp` INT(20),
	`sz` INT(20),
	`content` LONGBLOB(32),
);
    """)
    db.commit()
    db.close()


class handle_client:
    def __init__ (self, con=None, ip=None):
        print("New client\n")
        self.con = con
        self.ip = ip
        
        db = sqlite3.connect("messages.db", check_same_thread=False) # create connection for sqlite db
        cur = db.cursor # create db cursor
        
        
        
        self.rawdata = self.con.recv(0xffffff)
        self.encodedata = self.rawdata.replace(TX_START, b'')
        self.encodedata = self.encodedata.replace(TX_END, b'')
        self.data = base64.b64decode(self.encodedata)
        contents = funcs.parse_message(self.data[1:], CON)
        self.addr = contents[0].hex()

        print(f'[*] {self.ip} is {self.addr}')

        client_list.append({"ip" : self.ip, "addr": self.addr, "socket" : con})
        mysql_query = ("SELECT dest_addr, origin_addr, timestamp, sz, content, signature FROM messages WHERE dest_addr = %s AND timestamp > %s")
        cur.execute(mysql_query, (self.addr, datetime.datetime.fromtimestamp(int.from_bytes(contents[1], 'little'), datetime.timezone.utc)))

        for (dest_addr, origin_addr, timestamp, sz, content, signature) in cur: # send undelivered messages to client
            self.rawdata = TX_START + bytes.fromhex(dest_addr) + bytes.fromhex(origin_addr) + int((datetime.datetime.strptime(timestamp, datetime.timezone.utc)).timestamp()).to_bytes(4, 'little') + int(sz).to_bytes(4, 'little') + content + len(base64.b64decode(signature)).to_bytes(4, 'little') + base64.b64decode(signature).encode() + TX_END
            self.con.sendall(self.rawdata)


        while True:
            self.rawdata = self.con.recv(0xffffff)
            if not self.rawdata : break
            self.encodedata = self.rawdata.replace(TX_START, b'')
            self.encodedata = self.encodedata.replace(TX_END, b'')
            print(f'[*] {self.addr} sent (encoded)\n {self.encodedata} \n ')
            self.data = base64.b64decode(self.encodedata)
            print(f'[*] {self.addr} sent:\n {self.data} \n')
            contents = funcs.parse_message(self.data[1:], MESSAGE)
            destination_address = contents[0].hex()
            timestamp = int.from_bytes(contents[2], 'little')
            message_sz = int.from_bytes(contents[3], 'little')
            if (len(destination_address) != 64): 
                print(f'[*] Error: {self.addr} ({self.ip}) sent incorrectly formatted message: destination_address incorrect length') 
                break
            if (message_sz > pow(2, 32)-1):
                print(f'[*] Error: {self.addr} ({self.ip}) sent incorrectly formatted message: message_sz too large') 
                break
            
            for i in client_list:
                if i["addr"] == destination_address:
                    print(f'[*] Sending message to {i["addr"]} from {self.addr}')
                    i["socket"].sendall(self.rawdata)
                    break
            mysql_query = ("INSERT INTO messages(dest_addr, origin_addr, timestamp, sz, content, signature) VALUES(%s, %s, %s, %s, %s, %s)")
            cur.execute(mysql_query, (self.addr, destination_address, timestamp))

            cur.execute(mysql_query, (destination_address, self.addr, datetime.datetime.fromtimestamp(int.from_bytes(contents[2], 'little')), message_sz, contents[4], str(base64.b64encode(contents[6]))))
            db.commit()
if __name__ == '__main__':
    while True:
        new_con, new_ip = server_sock.accept()
        print(f'[*] {new_ip} connected')
        thread = threading.Thread(target = handle_client, args = (new_con, new_ip))
        thread.start()