## 1. **Challenge Decription**

<img width="912" height="500" alt="image" src="https://github.com/user-attachments/assets/16290c0e-fb19-48f8-afa0-18597a5d6205" />

Dưới đây là Write-up chi tiết cho bài **Related Messages**, tập trung vào kỹ thuật tấn công đa thức dựa trên mối liên hệ giữa hai thông điệp.

## 2. **Files**

### **chall.py**
```python
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD

Message = bytes_to_long(b"[redacted]")
Message_fixed = bytes_to_long(b"[redacted]")
e = 0x11 # e = 17
p = getPrime(1024)
q = getPrime(1024)
phi = (p-1) * (q-1)
d = inverse(e, phi)
N = p*q

ciphertext = pow(Message, e, N)
ciphertext2 = pow(Message_fixed, e, N)

print(ciphertext, ciphertext2)
print(Message - Message_fixed) # diff = -3
print(N)
```

### **output.txt**
Tệp tin chứa các giá trị số nguyên cực lớn cho `ciphertext` ($C_1$), `ciphertext2` ($C_2$), hiệu của hai thông điệp (`diff = -3`) và Modulo $N$

---

## 3. **Phân tích lỗ hổng**

### **Franklin-Reiter Related Message Attack**
Lỗ hổng xảy ra khi hai thông điệp có liên quan tuyến tính với nhau ($M_1$ và $M_2 = f(M_1)$) được mã hóa bằng cùng một số mũ công khai $e$ nhỏ trên cùng một Modulo $N$

Trong bài này:
- **Số mũ $e = 17$**: Đủ nhỏ để thực hiện các phép toán đa thức hiệu quả
- **Mối quan hệ:** `Message - Message_fixed = -3` $\implies M_2 = M_1 + 3$
- **Hệ phương trình:**
  1. $g_1(M_1) = M_1^{17} - C_1 \equiv 0 \pmod N$
  2. $g_2(M_1) = (M_1 + 3)^{17} - C_2 \equiv 0 \pmod N$

Bất cứ khi nào hai thông điệp có dạng $M_2 = aM_1 + b$, chúng ta có thể tìm ra $M_1$ bằng cách tìm **Ước chung lớn nhất (GCD)** của hai đa thức $g_1(x)$ và $g_2(x)$ trong vành đa thức $\mathbb{Z}_N[x]$



---

## 4. **Script Exploit (SageMath)**

Do việc tính toán GCD của đa thức bậc 17 trên Modulo 2048-bit rất phức tạp với Python thuần, chúng ta sử dụng **SageMath**:

[sage](https://sagecell.sagemath.org/)

```python
C1 = 348636...
C2 = 201982...
N = 173348...
diff = -3 # Tương đương M2 = M1 + 3
e = 17

P.<x> = PolynomialRing(Zmod(N))

g1 = x^e - C1
g2 = (x - diff)^e - C2 # (x - (-3))^e = (x + 3)^e

def composite_gcd(f1, f2):
    while f2:
        f1, f2 = f2, f1 % f2
    return f1.monic()

res = composite_gcd(g1, g2)

message_int = -res.coefficients()[0]

print(f"Message (int): {int(message_int)}")
print(f"Flag: {bytes.fromhex(hex(int(message_int))[2:]).decode()}")
```

---

## 5. **Kết quả**
<img width="1782" height="454" alt="image" src="https://github.com/user-attachments/assets/b92de176-f8fe-44a2-b576-b44c482fa345" />

---

FLAG: picoCTF{m3ssage_w1th_typ0}
----
