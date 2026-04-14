# 1. **Challenge Description**

<img width="897" height="539" alt="image" src="https://github.com/user-attachments/assets/f6d62d5b-93cd-4623-8acd-102b90d93a3f" />

**Description**: Can you find the flag in this disk image? Wrap what you find in the picoCTF flag format
**Hint**: 
- Create a Sleuthkit MAC timeline!
- Sloppy timestomping can yield strange (very old) timestamps

# 2. **Enumeration and Partition Analysis**

   Đầu tiên, chúng ta kiểm tra thông tin của file image để xác định định dạng hệ thống tệp tin (filesystem)

   ```bash 
flrsh@hxngnyez:~/workspace5$ file partition4.img
partition4.img: Linux rev 1.0 ext4 filesystem data, UUID=7a00e9da-98f8-4f0f-b257-95edf422d902 (extents) (64bit) (large files) (huge files)
```
Kết quả xác nhận đây là một phân vùng hệ thống tệp tin EXT4 thô. Chúng ta có thể sử dụng trực tiếp bộ công cụ The Sleuth Kit (TSK)

# 3. Filesystem Investigation & Timeline Creation
Dựa trên gợi ý về việc tạo mốc thời gian, chúng ta tiến hành trích xuất siêu dữ liệu (metadata) của toàn bộ phân vùng vào một tệp trung gian gọi là body file
Sử dụng lệnh ```fls -r -m / partition4.img > timeline.body``` để liệt kê danh sách các tệp và thư mục vào file timeline.body với các tham số có chức năng:

* -r (Recursive): Quét đệ quy qua toàn bộ cây thư mục để không bỏ sót dấu vết
* -m /: Xuất kết quả dưới dạng body file (định dạng cho máy đọc) với điểm gắn kết gốc là /

Vì nội dung body file rất khó đọc đối với con người, chúng ta sử dụng công cụ mactime để chuyển đổi các mốc thời gian Unix thành trình tự lịch sử có ngày tháng cụ thể
```bash
flrsh@hxngnyez:~/workspace5$ mactime -b timeline.body > timeline.txt
Old package separator "'" deprecated at /usr/bin/mactime line 154.
Old package separator "'" deprecated at /usr/bin/mactime line 167.
```
Lệnh này dùng để sắp xếp toàn bộ hoạt động của hệ thống tệp như Tạo, Truy cập, Chỉnh sửa theo thứ tự thời gian với -b ;à chỉ định tệp nguồn là body file đã tạo

# 4. **Timeline Analysis and Anomaly Detection**
Phân tích những dòng đầu tiên của tệp timeline.txt để tìm kiếm các mốc thời gian cũ bất thường
```bash
flrsh@hxngnyez:~/workspace5$ head timeline.txt
Wed Jan 02 1985 00:00:00       41 macb r/rrw-r--r-- 0        0        4945     /bin/bcab
Tue Oct 19 2021 00:54:17      451 ma.. r/rrw-r--r-- 0        0        64994    /usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub
                              451 ma.. r/rrw-r--r-- 0        0        64995    /usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub
                              451 ma.. r/rrw-r--r-- 0        0        64996    /usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-524d27bb.rsa.pub
                              451 ma.. r/rrw-r--r-- 0        0        64997    /usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub
                              451 ma.. r/rrw-r--r-- 0        0        64998    /usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub
                              451 ma.. r/rrw-r--r-- 0        0        64999    /usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58cbb476.rsa.pub
                              451 ma.. r/rrw-r--r-- 0        0        65000    /usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58e4f17d.rsa.pub
                              451 ma.. r/rrw-r--r-- 0        0        65001    /usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-5e69ca50.rsa.pub
                              451 ma.. r/rrw-r--r-- 0        0        65002    /usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-60ac2099.rsa.pub
```
hmmm, hầu hết các tệp hệ thống đều có mốc thời gian từ năm 2021 trở đi, nhưng tệp /bin/bcab lại có mốc thời gian từ Thứ Tư, ngày 02 tháng 01 năm 1985. Đây là dấu hiệu rõ rệt của Timestomping - author đã cố tình chỉnh sửa thời gian để tệp tin ẩn trong quá khứ

# 5. **Inode Investigation and Data Recovery**
Dòng thời gian báo tệp bcab nằm ở Inode 41. Tuy nhiên, khi kiểm tra Inode 41 trực tiếp, dữ liệu trả về lại là một symbolic link không chứa flag. Điều này cho thấy có sự mâu thuẫn giữa nhật ký hệ thống (Journal) và cấu trúc đĩa hiện tại. Chúng ta cần tìm vị trí thực sự của tệp bcab trên đĩa, và fls sẽ giúp chuyện này
```bash
flrsh@hxngnyez:~/workspace5$ fls -r partition4.img | grep "bcab"
++++++ r/r * 3274(realloc):     .apk.10e29c5d76e1321cf21bcabaf84195017261637442b6036e
+ r/r 4945:     bcab
flrsh@hxngnyez:~/workspace5$
```
alr, dữ liệu thực sự nằm ở Inode 4945. Chúng ta sử dụng lệnh icat để trích xuất nội dung từ Inode này, ```icat partition4.img 4945 > output.txt``` sẽ được tôi sử dụng để trích xuất nraw data của tệp tin dựa trên Inode mà không cần mount phân vùng
```bash
flrsh@hxngnyez:~/workspace5$ icat partition4.img 4945 > output.txt
flrsh@hxngnyez:~/workspace5$ cat output.txt
NzFtMzExbjNfMHU3MTEzcl9oM3JfNDNhMmU3YWYK
```
# 6. **Data Decoding and Flag Recovery**
Chuỗi ký tự vừa nhận được có cấu trúc mã Base64. Chúng ta cần tiến hành giải mã để tìm nội dung flag, có một lệnh base64 -d (decode) sẽ giúp ta chuyển file đó thành ascii 

Kết quả:
```bash
flrsh@hxngnyez:~/workspace5$ cat output.txt | base64 -d
71m311n3_0u7113r_h3r_43a2e7af
```

   FLAG: picoCTF{71m311n3_0u7113r_h3r_43a2e7af}
--------------------------------------------------------------------------------
