## 1. **Challenge Decription**

<img width="912" height="500" alt="image" src="https://github.com/user-attachments/assets/16290c0e-fb19-48f8-afa0-18597a5d6205" />

## 2. Files
### **chall.py**
```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes

key = bytes_to_long(get_random_bytes(126))

def steplfsr(lfsr):
    b7 = (lfsr >> 7) & 1
    b5 = (lfsr >> 5) & 1
    b4 = (lfsr >> 4) & 1
    b3 = (lfsr >> 3) & 1

    feedback = b7 ^ b5 ^ b4 ^ b3
    lfsr = (feedback << 7) | (lfsr >> 1)
    return lfsr

def encrypt_lfsr(pt_bytes):
    output = bytearray()
    lfsr = key & 0xFF
    for p in pt_bytes:
        lfsr = steplfsr(lfsr)
        ks = lfsr
        output.append(p ^ ks)
    return bytes_to_long(bytes(output))

pt = b"[redacted]"
ct = encrypt_lfsr(pt)

print(long_to_bytes(ct).hex())
```

### **output.txt**
```text
21c1b705764e4bfdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9
```

---

## 2. **Phân tích lỗ hổng**

### **Cơ chế LFSR (Linear Feedback Shift Register)**
LFSR là một thanh ghi dịch mà bit đầu vào (feedback) được tính toán từ hàm tuyến tính (XOR) của các bit trạng thái trước đó



Trong tệp `chall.py`:
- **Taps (Vị trí bit phản hồi):** Các bit tại vị trí 7, 5, 4, 3 được dùng để XOR tạo ra bit mới
- **Cơ chế dịch:** Bit phản hồi được đưa vào vị trí cao nhất (bit 7), các bit còn lại dịch sang phải 1 đơn vị
- **Trạng thái (State):** LFSR này hoạt động trên **8-bit**

### **Lỗ hổng chí mạng (Weak Seed/Small State Space)**
Mặc dù biến `key` ban đầu được tạo ngẫu nhiên 126 bytes ($2^{1008}$ khả năng), nhưng thuật toán mã hóa chỉ sử dụng:
```python
lfsr = key & 0xFF
```
Dòng lệnh này chỉ lấy **8 bit cuối cùng** của `key` để làm trạng thái khởi tạo (seed). Điều này dẫn đến việc không gian khóa chỉ có đúng $2^8 = 256$ trường hợp (từ 0 đến 255). Đây là một con số cực kỳ nhỏ, cho phép chúng ta thực hiện tấn công **Brute-force** chỉ trong chưa đầy 1 giây

---

## 3. **Script Exploit**

```python
from Crypto.Util.number import long_to_bytes

ct_hex = "21c1b705764e4bfdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9"
ct_bytes = bytes.fromhex(ct_hex)

def steplfsr(lfsr):
    b7 = (lfsr >> 7) & 1
    b5 = (lfsr >> 5) & 1
    b4 = (lfsr >> 4) & 1
    b3 = (lfsr >> 3) & 1
    feedback = b7 ^ b5 ^ b4 ^ b3
    lfsr = (feedback << 7) | (lfsr >> 1)
    return lfsr & 0xFF

for state in range(256):
    pt = bytearray()
    curr_lfsr = state
    for c in ct_bytes:
        curr_lfsr = steplfsr(curr_lfsr)
        pt.append(c ^ curr_lfsr)
    
    if b"pico" in pt:
        print(f"Trạng thái khởi tạo: {state}")
        print(f"Flag: {pt.decode()}")
        break
```

---

## 4. **Kết quả**
```bash
flrsh@hxngnyez:~/workspace5$ python3 k.py
Trạng thái khởi tạo: 162
Flag: picoCTF{l1n3ar_f33dback_sh1ft_r3g}
```

Flag: picoCTF{l1n3ar_f33dback_sh1ft_r3g}
----
