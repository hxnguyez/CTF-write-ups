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
## 2. Dynamic Debugging
