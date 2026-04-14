# 1. **Challenge Description**

<img width="896" height="498" alt="image" src="https://github.com/user-attachments/assets/95a1b079-2b3f-4d74-8a7e-5ae37b4ad213" />


# 2. **Files**

### **encrypt.py**
```python
from random import randint
from sage.all import *

N = 48
p = 3
q = 509

R = PolynomialRing(ZZ, 'x')
x = R.gen()
R_modq = PolynomialRing(Integers(q), 'x').quotient(x**N - 1, 'xbar')
R_modp = PolynomialRing(Integers(p), 'x').quotient(x**N - 1, 'xbar')

def gen_poly():
    return R([randint(-1,1) for _ in range(N)])

def gen_msg(text):
    binary_str = ''.join(format(ord(char), '08b') for char in text)
    padding_length = (N - (len(binary_str) % N)) % N
    binary_str += '0' * padding_length
    chunks = [binary_str[i:i+N] for i in range(0, len(binary_str), N)]
    polynomials = [R([int(bit) for bit in chunk]) for chunk in chunks]
    return polynomials

def encrypt(h, m):
    r = gen_poly()
    return R_modq(p*(h*r) + m)

def generate_keys():
    while True:
        f = gen_poly()
        g = gen_poly()
        try:
            f_p_inv = R_modp(f)**-1
            f_q_inv = R_modq(f)**-1
            break
        except:
            continue
    h = R_modq(p*(f_q_inv*g))
    private_key = (f, g, f_p_inv, f_q_inv)
    public_key = h
    return public_key, private_key
```

### **public.txt**
Tệp tin này cung cấp các tham số công khai:
- $N = 48$ (Bậc của đa thức)
- $p = 3$, $q = 509$ (Modulo)
- $h$: Đa thức khóa công khai (Public Key)
- $ct$: Danh sách các khối đa thức bản mã (Ciphertext)

---

# 3. **Phân tích lỗ hổng**

### **Hệ mật mã NTRU**
Hệ mật này dựa trên bài toán **SVP (Shortest Vector Problem)** trong một mạng lưới (Lattice). Độ an toàn của nó phụ thuộc rất lớn vào giá trị của bậc đa thức $N$


### **Vấn đề về tham số (Small N)**
Trong bài tập này, giá trị $N = 48$ là **cực kỳ nhỏ**. Theo các tiêu chuẩn an ninh hiện đại, $N$ thường phải lớn hơn $500$ để chống lại các thuật toán rút gọn mạng lưới. Với $N=48$, mạng lưới NTRU có kích thước $2N \times 2N = 96 \times 96$, một kích thước mà thuật toán **LLL (Lenstra–Lenstra–Lovász)** có thể xử lý trong chưa đầy một giây để tìm ra các vector ngắn

### **Xây dựng ma trận Lattice**
Khóa công khai $h$ được tạo ra từ $h \equiv p \cdot f^{-1} \cdot g \pmod q$. Điều này có nghĩa là tồn tại một đa thức $K$ sao cho:
$$f \cdot h = p \cdot g + K \cdot q$$
Chúng ta có thể xây dựng một ma trận mạng lưới $M$ có dạng:
$$M = \begin{pmatrix} I_{N \times N} & H_{N \times N} \\ 0_{N \times N} & qI_{N \times N} \end{pmatrix}$$
Trong đó $H$ là ma trận tuần hoàn biểu diễn phép nhân đa thức với $h$. Vector $(f, g)$ sẽ là một vector ngắn trong mạng lưới được tạo ra bởi ma trận này

---

# 4. **Script Exploit (SageMath)**

```python
from sage.all import *

N = 48
p = 3
q = 509
h_coeffs = [467, 204, 459, 435, 40, 88, 86, 107, 358, 235, 12, 500, 491, 90, 44, 414, 474, 130, 199, 229, 274, 59, 298, 253, 70, 107, 64, 134, 240, 349, 419, 159, 109, 437, 357, 133, 244, 423, 205, 115, 405, 464, 458, 174, 85, 59, 503, 301]
ct = [[392, 352, 271, 299, 247, 452, 360, 362, 23, 459, 307, 15, 5, 178, 451, 130, 358, 88, 218, 91, 462, 385, 166, 435, 363, 32, 326, 17, 322, 271, 2, 193, 126, 311, 135, 232, 51, 240, 141, 104, 172, 227, 465, 323, 376, 135, 378, 41], [33, 344, 504, 138, 202, 327, 208, 248, 82, 9, 79, 143, 369, 101, 158, 222, 122, 366, 331, 433, 445, 217, 16, 57, 242, 455, 170, 376, 221, 469, 130, 14, 413, 20, 43, 75, 74, 148, 278, 7, 369, 379, 153, 75, 443, 42, 273, 171], [295, 304, 78, 132, 149, 287, 322, 39, 308, 274, 341, 100, 184, 496, 11, 157, 228, 475, 184, 504, 233, 288, 316, 385, 252, 20, 120, 28, 92, 400, 500, 56, 131, 476, 435, 281, 177, 474, 358, 254, 97, 156, 329, 37, 184, 312, 500, 422], [381, 28, 346, 142, 53, 18, 214, 89, 375, 408, 294, 497, 104, 99, 444, 429, 489, 275, 156, 76, 19, 449, 229, 268, 328, 57, 383, 374, 76, 339, 498, 127, 24, 88, 289, 126, 409, 230, 364, 226, 414, 458, 345, 241, 324, 455, 314, 349], [253, 478, 368, 299, 464, 214, 191, 155, 48, 318, 376, 83, 215, 248, 59, 114, 16, 252, 220, 113, 120, 226, 253, 31, 269, 403, 59, 271, 243, 427, 132, 362, 491, 41, 18, 486, 396, 34, 159, 351, 505, 329, 96, 479, 226, 182, 404, 227], [457, 90, 115, 229, 460, 65, 136, 421, 263, 482, 426, 49, 131, 205, 269, 153, 111, 14, 336, 338, 118, 209, 444, 208, 412, 222, 9, 338, 192, 10, 121, 353, 318, 410, 235, 416, 223, 309, 489, 226, 391, 452, 66, 395, 106, 391, 260, 411]]

R = PolynomialRing(ZZ, 'x')
x = R.gen()
R_modq = PolynomialRing(Integers(q), 'x').quotient(x**N - 1, 'xbar')
R_modp = PolynomialRing(Integers(p), 'x').quotient(x**N - 1, 'xbar')

print("[*] Đang xây dựng ma trận Lattice...")
M = Matrix(ZZ, 2*N, 2*N)
for i in range(N):
    M[i, i] = 1
    for j in range(N):
        # Tạo ma trận tuần hoàn cho h
        M[i, N + j] = h_coeffs[(j - i) % N]
    M[N + i, N + i] = q

print("LLL...")
L = M.LLL()

f_poly = None
for row in L:
    f_candidate = R(list(row[:N]))
    try:
        f_p_inv = R_modp(f_candidate)**-1
        f_q_inv = R_modq(f_candidate)**-1
        f_poly = f_candidate
        print(f"key f: {f_poly.list()}")
        break
    except:
        continue

if not f_poly:
    print("Không tìm thấy scret key!")
    exit()

print("giải mã các khối...")
f_q = R_modq(f_poly)
f_p_inv = R_modp(f_poly)**-1

full_binary = ""
for c_list in ct:
    c_poly = R_modq(c_list)

    a = f_q * c_poly

    a_coeffs = [(int(coeff) + q//2) % q - q//2 for coeff in a.list()]

    m_poly = f_p_inv * R_modp(a_coeffs)
    
    m_list = m_poly.list()
    m_list += [0] * (N - len(m_list))
    full_binary += "".join(str(bit) for bit in m_list)

flag = ""
for i in range(0, len(full_binary), 8):
    byte = full_binary[i:i+8]
    if len(byte) < 8: break
    flag += chr(int(byte, 2))

print(f"\nFLAG: {flag.strip(chr(0))}")
```

---

# 5. **Kết quả**
<img width="1775" height="547" alt="image" src="https://github.com/user-attachments/assets/e9a1806b-0357-4a60-887e-d963e5f85f17" />


FLAG: **picoCTF{th4ts_s0_N0t_TRU3_d15f40a6}**
-----
