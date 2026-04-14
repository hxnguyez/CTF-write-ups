# 1. **Challenge Description**
<img width="893" height="470" alt="image" src="https://github.com/user-attachments/assets/3c1f36b1-777c-4381-9e2a-ef89ff3369c4" />


# 2. **file**

### **chall.py**
```python
# Các hàm quan trọng bị vô hiệu hóa tính phi tuyến:
def sub_word(word):
    return word

def rcon(word):
    return word

def sub_bytes(state):
    return state

# Thuật toán mã hóa vẫn giữ cấu trúc AES chuẩn nhưng chỉ còn các phép toán tuyến tính:
# XOR Key, ShiftRows, MixColumns.
```

### **output.txt**
- $C_{pt1} = \text{d7481d89f1aaf5a857f56edd2ae8994c}$ (Bản mã của dữ liệu mẫu)
- $C_{flag} = \text{8c7d66558130eb5796d131beb43c9934}$ (Bản mã của Flag)

---

# 3. **Phân tích lỗ hổng**

### **Tính tuyến tính của hệ thống (Linearity)**
Trong thuật toán AES chuẩn, lớp **SubBytes** (sử dụng S-Box) là thành phần duy nhất tạo ra tính phi tuyến, giúp chống lại các cuộc tấn công đại số. Trong bài này, hàm `sub_bytes` và các hàm liên quan trong quá trình tạo khóa (`sub_word`, `rcon`) đều là các hàm định danh (trả về giá trị gốc)

Khi đó, toàn bộ quy trình AES có thể được xem như một phép biến đổi tuyến tính $L$ kết hợp với phép XOR khóa $K$:
$$AES(P, K) = L(P) \oplus f(K)$$



Vì tính chất tuyến tính này, ta có hệ thức:
$$AES(P_1 \oplus P_2, 0) = AES(P_1, K) \oplus AES(P_2, K)$$
Điều này cho phép chúng ta triệt tiêu hoàn toàn ảnh hưởng của khóa bí mật bằng cách XOR hai bản mã với nhau

---

# 4. **Hướng giải quyết**

1. **Triệt tiêu Key:** Sử dụng cặp Plaintext mẫu ($PT_1$) và Ciphertext mẫu ($CT_1$) để tính toán giá trị hằng số $Const = AES(0, Key)$
   $$Const = CT_1 \oplus AES(PT_1, 0)$$
2. **Khử nhiễu Flag:** Tính toán giá trị của Flag khi đi qua các bước tuyến tính với khóa bằng 0:
   $$AES(Flag, 0) = CT_{flag} \oplus Const$$
3. **Đảo ngược các phép toán tuyến tính:**
   - **Nghịch đảo MixColumns:** Nhân với ma trận nghịch đảo tương ứng trong trường $GF(2^8)$
   - **Nghịch đảo ShiftRows:** Dịch ngược lại các byte về vị trí ban đầu
   - Thực hiện đảo ngược đủ 10 vòng mã hóa để khôi phục lại nội dung Flag

---

# 5. **Script Exploit**

```python
from pwn import xor

# Dữ liệu từ output.txt và bước tính toán trung gian
aes_flag_zero = "08af41e8585fd557754a714a0a1ec079"

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        a <<= 1
        if a & 0x100: a ^= 0x11b
        b >>= 1
    return p

def inv_mix_columns(s):
    ss = [[0] * 4 for _ in range(4)]
    inv_m = [[0x0e, 0x0b, 0x0d, 0x09], [0x09, 0x0e, 0x0b, 0x0d], [0x0d, 0x09, 0x0e, 0x0b], [0x0b, 0x0d, 0x09, 0x0e]]
    for c in range(4):
        for r in range(4):
            val = 0
            for i in range(4):
                val ^= gmul(inv_m[r][i], int(s[i][c], 16))
            ss[r][c] = hex(val)[2:].zfill(2)
    return ss

def inv_shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]
    return state

state = [[0]*4 for _ in range(4)]
bytes_list = [aes_flag_zero[i:i+2] for i in range(0, 32, 2)]
for i in range(16): state[i%4][i//4] = bytes_list[i]

# Đảo ngược vòng 10
state = inv_shift_rows(state)

# Đảo ngược 9 vòng lặp còn lại
for _ in range(9):
    state = inv_mix_columns(state)
    state = inv_shift_rows(state)

flag_hex = "".join(state[i%4][i//4].zfill(2) for i in range(16))
print(f"Flag: {bytes.fromhex(flag_hex).decode()}")
```

---

# 6. **Kết quả**
```bash
flrsh@hxngnyez:~/workspace$ python3 k.py
Flag: picoCTF{spi1cy!}
```

FlAG: **picoCTF{spi1cy!}**
-------
