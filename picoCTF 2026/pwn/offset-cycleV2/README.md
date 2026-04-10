# PicoCTF 2026: Offset-Cycle

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

#define BUFSIZE 372
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
#define BUFSIZE 372
#define CANARY_SIZE 4
#define FLAGSIZE 64
```
