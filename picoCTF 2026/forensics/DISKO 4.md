# 1. Challenge Description

<img width="898" height="527" alt="image" src="https://github.com/user-attachments/assets/9d42bf2f-f84b-49ad-83dc-707b58c21c3c" />

Description: The agents interrupted the perpetrator's disk deletion routine. Can you recover the hidden flag from this disk image?

# 2. Enumeration and Partition Analysis
Đầu tiên, chúng ta kiểm tra thông tin cơ bản của tệp tin image để xác định định dạng và cấu trúc hệ thống tệp

```Bash
flrsh@hxngnyez:~/workspace5$ file disko-4.dd
disko-4.dd: DOS/MBR boot sector, code offset 0x58+2, OEM-ID "mkfs.fat", Media descriptor 0xf8, sectors/track 32, heads 8, sectors 204800 (volumes > 32 MB), FAT (32 bit), sectors/FAT 1576, serial number 0x49838d0b, unlabeled
```
Hệ thống nhận diện đây là một phân vùng FAT32. Tiếp theo, chúng ta sử dụng strings để tìm kiếm nhanh từ khóa "pico" nhằm xác định xem có dấu vết nào của flag trong dữ liệu thô hay không.

```Bash
flrsh@hxngnyez:~/workspace5$ strings -t d disko-4.dd | grep -i "pico"
10074662 pico desta partici
10078477 Description-it.UTF-8: Utilizzo tipico di questa partizione:
10087641 pico desta parti
10267589 Description-it.UTF-8: Utilizzo tipico:
10268827 pico:
16511904 Aug 30 01:59:37 debootstrap: update-alternatives: using /bin/nano to provide /usr/bin/pico (pico) in auto mode
16617804 Aug 30 02:00:42 in-target:   mailx | mailutils snmptrapd libttspico-utils espeak mbrola
18191039 Description: small, friendly text editor inspired by Pico - udeb
48188912 MESSAGE=[system] Activating via systemd: service name='org.bluez' unit='dbus-org.bluez.service' requested by ':1.81' (uid=1000 pid=12105 comm="/usr/share/code/code Desktop/picoctf-2025")
49777336 MESSAGE=[system] Activating via systemd: service name='org.bluez' unit='dbus-org.bluez.service' requested by ':1.66' (uid=1000 pid=43129 comm="/usr/share/code/code Desktop/picoctf-2025")
51049904 MESSAGE=[system] Activating via systemd: service name='org.bluez' unit='dbus-org.bluez.service' requested by ':1.65' (uid=1000 pid=2141 comm="/usr/share/code/code Desktop/picoctf-2025")
52784336 MESSAGE=[system] Activating via systemd: service name='org.bluez' unit='dbus-org.bluez.service' requested by ':1.65' (uid=1000 pid=2584 comm="/usr/share/code/code Desktop/picoctf-2025")
```
Kết quả cho thấy nhiều tham chiếu đến picoctf-2025 và các tệp cấu hình liên quan đến trình soạn thảo văn bản pico. Điều này xác nhận đây là phân vùng mục tiêu chính xác

# 3. Filesystem Investigation
Sử dụng công cụ fls từ bộ The Sleuth Kit để liệt kê các danh mục và tệp tin trong image. Chúng ta đặc biệt chú ý đến các tệp tin đã bị xóa (thường được đánh dấu bằng dấu * trong kết quả của fls)

```bash
flrsh@hxngnyez:~/workspace5$ fls -r -d disko-4.dd
r/r * 522629:   log/messages
r/r * 532021:   log/dont-delete.gz
```

ta phát hiện một tệp nén đáng ngờ mang tên dont-delete.gz nằm tại Inode 532021. Tên tệp dont-delete.gz là một manh mối rõ ràng cho thấy đây là nơi giấu dữ liệu quan trọng

# 4. Data Recovery
Sử dụng công cụ icat để trích xuất nội dung của tệp tin dựa trên số Inode đã tìm thấy, sau đó tiến hành giải nén để đọc nội dung bên trong

```Bash
flrsh@hxngnyez:~/workspace5$ icat disko-4.dd 532021 > evidence.gz
flrsh@hxngnyez:~/workspace5$ gunzip evidence.gz
```
# 5. Flag Recovery
Sau khi giải nén, chúng ta kiểm tra nội dung của tệp evidence vừa thu được

```Bash
flrsh@hxngnyez:~/workspace5$ cat evidence
Here is your flag
picoCTF{d3l_d0n7_h1d3_w3ll_bc352004}
```

FLAG: picoCTF{d3l_d0n7_h1d3_w3ll_bc352004}
-------
