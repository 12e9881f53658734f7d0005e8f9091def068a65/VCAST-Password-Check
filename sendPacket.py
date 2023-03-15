from scapy.all import IP, TCP, send, sr1, sr
from random import randint

def preparePassword(password):
    return f"CHECKPASSWORD\r\n{password}\r\n\r\n"

def sendPasswordCheckRequest(boardIP, passwordToCheck):
    sp = randint(1024,65535)
    ip = IP(dst=boardIP)

    syn = TCP(sport=sp, dport=8121, flags="S", seq=randint(9999, 99999))
    synAck1 = sr1(ip/syn, verbose=False)

    ack = TCP(sport=sp, dport=8121, flags="A", seq=synAck1.ack, ack=synAck1.seq + 1)
    send(ip/ack, verbose=False)

    tcp = TCP(sport=sp, dport=8121, flags="PA", seq=synAck1.ack, ack=synAck1.seq + 1) # PSH = 0x08
    packet = ip/tcp/preparePassword(passwordToCheck)
    res = sr(packet, verbose=False, filter="tcp[13] & 8!=0")

    checkStatusPacket = None
    for e in res[0][0]:
        if b"check" in e.load:
            checkStatusPacket = e
            break
    
    if checkStatusPacket:
        fin = TCP(sport=sp, dport=8121, flags="FA", seq=checkStatusPacket.ack, ack=checkStatusPacket.seq + 16)
        finRes = sr1(ip/fin)
        ack = TCP(sport=sp, dport=8121, flags="A", seq=finRes.ack, ack=finRes.seq + 1)
        send(ip/ack)

        if b"failed" not in checkStatusPacket.load:
            return passwordToCheck
    else:
        return False

print(sendPasswordCheckRequest("172.28.67.113", "passwordOmG"))