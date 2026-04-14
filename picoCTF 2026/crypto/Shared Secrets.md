## 1. **Challenge Description**

<img width="898" height="559" alt="image" src="https://github.com/user-attachments/assets/ed002b57-8f63-40b9-a847-93a3400f79cb" />


## 2. **Concept: Diffie-Hellman Key Exchange**
Bài toán dựa trên giao thức trao đổi khóa **Diffie-Hellman**, một phương pháp cho phép hai bên thiết lập một khóa bí mật chung qua một kênh truyền thông không an toàn

**Quy trình cơ bản:**
1. Hai bên thống nhất các số công khai: số nguyên tố lớn $p$ và cơ số $g$
2. Mỗi bên tự chọn một số bí mật riêng ($a$ và $b$)
3. Họ tính toán và gửi cho nhau các giá trị công khai:
   - Server gửi $A = g^a \pmod{p}$
   - Client gửi $B = g^b \pmod{p}$
4. Khóa dùng chung (**Shared Secret**) được tính bằng: $S = A^b \pmod{p} = B^a \pmod{p}$

## 3. **Vulnerability Analysis**
Trong mật mã học, độ an toàn của Diffie-Hellman dựa trên việc kẻ tấn công không thể tìm được số bí mật $a$ hoặc $b$ từ các giá trị công khai $A, B, g, p$ (Bài toán logarit rời rạc)

Tuy nhiên, trong bài này:
- File `message.txt` cung cấp đầy đủ $g, p, A$
- Đặc biệt, giá trị bí mật $b$ của Client **đã bị lộ hoàn toàn**
- Khi đã có $A$ và $b$, bất kỳ ai cũng có thể tính được **Shared Secret** $S$ theo công thức: $$S = A^b \pmod{p}$$

## 4. **Exploitation Steps**

### Bước 1: Trích xuất dữ liệu
Lấy các giá trị $g, p, A, b$ và chuỗi `enc` (hex) từ tệp `message.txt`

### Bước 2: Tính toán Shared Key
Sử dụng hàm `pow(base, exp, mod)` trong Python để tính toán giá trị $S$ cực lớn một cách nhanh chóng. Theo mã nguồn `encryption.py`, khóa thực tế dùng để mã hóa chỉ là 1 byte cuối cùng của $S$:
```python
shared_key = pow(A, b, p) % 256
```

### Bước 3: Giải mã XOR
Vì thuật toán sử dụng phép toán XOR (`x ^ (shared % 256)`), chúng ta chỉ cần thực hiện XOR ngược lại bản mã `enc` với `shared_key` để thu được bản rõ

## 5. **Solution Script**
```python
p = 1653798930689987750372209240014380521131540183716217687164747711336243702962818359267822691525697642105558753651223568056089606926425342081267821725904109431430327153613733358950243154522848602494020618427146508586350079988809469424456886589329449769221123659126892760967096413248127035734431548987006011015808526671
A = 771122236020803078829911570090382183223626843114693013412703353349864301811612864849857638111588507084769437566078749825291937213523446695097948166153379036322108656350710200734137906115055446496743841090323252143278700024424965369059879247648625799137192258413471893876530475007392243768366999108564494255853654467
b = 502087552249276796768894199149546386713173741864561762918671131549146319658647813949433247424965048798816294966029262647803764533595143429273283374211302160540685383641060542870573303301014875733971557824236009184578986290165659257363419797500816452080900496604781986251988455903195756181696996025184087945715324970
enc = bytes.fromhex("cfd6dcd0fcebf9c4dbd7e0cc8cdccd8ccbe0dddb8c87d98c8889c2")

shared = pow(A, b, p)
key = shared % 256

flag = "".join([chr(x ^ key) for x in enc])
print(flag)
```

**FLAG:** `picoCTF{dh_s3cr3t_bd38f376}`
------
