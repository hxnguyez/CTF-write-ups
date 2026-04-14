# 1. **Challenge Description**
<img width="887" height="828" alt="image" src="https://github.com/user-attachments/assets/2b173f3f-d97d-4306-8d1a-6bab2ba2d47c" />


# 2. **file**

### **output.txt**
```text
LFSR Initial State:
[0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1]

LFSR Taps:
[63, 61, 60, 58]

Encrypted Flag:
8f0e6d0f5b0dc1db201948b9e0cebd8f9195f08c0c8364a8741150da8e5bc72838338e7e04fbddef0c6260a4eb758417
```

---

# 3. **Phân tích lỗ hổng**

### **Cơ chế dẫn xuất khóa (Key Derivation)**
Hệ thống sử dụng một bộ sinh số giả ngẫu nhiên là **LFSR (Linear Feedback Shift Register)** để tạo ra 128 bit, sau đó chuyển đổi chúng thành 16 byte để làm khóa cho thuật toán mã hóa AES-128

### **Vấn đề bảo mật**
Trong mật mã học, độ an toàn của các hệ thống kết hợp thường nằm ở tính bí mật của các tham số khởi tạo (Seed/State). Trong bài này:
* **Lộ diện trạng thái (Exposed State):** Toàn bộ 64 bit trạng thái ban đầu của LFSR bị rò rỉ trong file `output.txt`
* **Lộ diện đa thức phản hồi (Exposed Taps):** Các vị trí Taps `[63, 61, 60, 58]` dùng để tính toán bit phản hồi được cung cấp công khai

Khi biết cả trạng thái khởi tạo và các Taps, dòng khóa (keystream) đầu ra hoàn toàn có thể dự đoán được 100%. Bất kỳ ai cũng có thể tái tạo lại chính xác chuỗi 128 bit mà LFSR đã tạo ra, từ đó khôi phục lại khóa AES và giải mã Flag



---

# 4. **Script Exploit**

```python
from Crypto.Cipher import AES

initial_state = [0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1]
taps = [63, 61, 60, 58]
ciphertext_hex = "8f0e6d0f5b0dc1db201948b9e0cebd8f9195f08c0c8364a8741150da8e5bc72838338e7e04fbddef0c6260a4eb758417"

def get_keystream(state, taps, length):
    curr = list(state)
    res = []
    for _ in range(length):
        res.append(curr[0])
        fb = 0
        for t in taps:
            fb ^= curr[t]
        curr = curr[1:] + [fb]
    return res

bits = get_keystream(initial_state, taps, 128)
key_bytes = []
for i in range(0, 128, 8):
    byte_val = int("".join(map(str, bits[i:i+8])), 2)
    key_bytes.append(byte_val)

aes_key = bytes(key_bytes)
ciphertext = bytes.fromhex(ciphertext_hex)
cipher = AES.new(aes_key, AES.MODE_ECB)
decrypted = cipher.decrypt(ciphertext)

print(f"Derived AES Key (hex): {aes_key.hex()}")
print(f"Flag: {decrypted.decode('utf-8', errors='ignore').strip()}")
```

---

# 5. **Kết quả**

```python
flrsh@hxngnyez:~/workspace5$ python3 k.py
Derived AES Key (hex): 25ec96954d8bc45b2d7798a9fa0e1236
Flag: picoCTF{scr8mbledt_flvg_7eb8c19e}
```

FLAG: picoCTF{scr8mbledt_flvg_7eb8c19e}
---
