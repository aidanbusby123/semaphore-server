import sys
import bisect

MESSAGE = 0x01
PUBKEY_REQ = 0x02
PUBKEY_X = 0x03
KEY_X = 0x04
CON = 0x05

def parse_message(buf, type):
    message_tuple = [None] * 12
    if len(buf) >= 72:
        if type == MESSAGE:
            message_tuple[0] = buf[0:32]
            message_tuple[1] = buf[32:64]
            message_tuple[2] = buf[64:68]
            message_tuple[3] = buf[68:72]
            content_len = int.from_bytes(message_tuple[3], 'little')
            message_tuple[4] = buf[72:72+content_len]
            message_tuple[5] = buf[72+content_len:76+content_len]
            signature_len = int.from_bytes(message_tuple[5], 'little')
            message_tuple[6] = buf[76+content_len:76+content_len+signature_len]
        elif type == CON:
            message_tuple[0] = buf[0:32]
            message_tuple[1] = buf[32:36]
            message_tuple[2] = buf[36:40]
            content_len = int.from_bytes(message_tuple[2], 'little')
            message_tuple[3] = buf[40:40+content_len]
            message_tuple[4] = buf[40+content_len:40+content_len+4]
            signature_len = int.from_bytes(message_tuple[4], 'little')
            message_tuple[5] = buf[44+content_len:44+content_len+signature_len]
    return message_tuple
