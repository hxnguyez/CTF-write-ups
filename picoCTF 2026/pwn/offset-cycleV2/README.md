# PicoCTF 2026: Offset-Cycle

**Category:** Binary Exploitation  |
**Point:** 400 |
**Solve:** 895  

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

* Time: 80s to solve before deleting automatically
* Target: Buffer Overflow to ```win()``` func to read flag

### 2. **C file Analysis**
After connected to server, we can run ```./start``` and read C file generated

<img width="922" height="840" alt="image" src="https://github.com/user-attachments/assets/13e60182-ffae-423a-a3da-94e37333f7d6" />

Now, **C File**:
* define a random buffer in each session
* win() contains flag.txt
* vuln() uses 

=> This is a Buffer Overflow vuln

### 3. **Binary Analysis**

<img width="454" height="246" alt="image" src="https://github.com/user-attachments/assets/dd09863a-584f-4895-b300-e1aa08d2c1d8" />


Using ```checksec```, we know:
* Architecture: i386
* No PIE
* NX enable (Cannot shellcode)

### 4. **Exploitation Strategy**
