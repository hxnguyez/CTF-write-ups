## 1. **Challenge Description**

<img width="905" height="591" alt="image" src="https://github.com/user-attachments/assets/0bdab4fd-633a-4f84-a1c5-b371d8d2f969" />


## 2. **Concept: Weak Key Generation & PRNG Seeds**
Tính an toàn của các thuật toán mã hóa đối xứng như AES phụ thuộc hoàn toàn vào độ ngẫu nhiên và tính bí mật của khóa

**Vấn đề trong bài này:**
Khóa được tạo bằng cách băm giá trị `timestamp` (thời gian thực tính bằng giây)
- `key = sha256(str(timestamp).encode()).digest()[:16]`

Vì thời gian là một đại lượng có thể dự đoán và giới hạn được, khóa này không có đủ độ hỗn loạn (Entropy). Nếu kẻ tấn công biết được khoảng thời gian (khoảng vài giờ hoặc vài ngày) mà tệp tin được mã hóa, họ có thể thử tất cả các giá trị thời gian khả thi để tạo lại khóa tương ứng



## 3. **Vulnerability Analysis**
1. **Dự đoán được không gian khóa:** Gợi ý cung cấp mốc thời gian `1770242628 UTC`. Kẻ tấn công chỉ cần quét xung quanh mốc này (Brute-force) thay vì phải thử $2^{128}$ trường hợp như lý thuyết của AES-128
2. **AES Mode ECB:** Chế độ này không sử dụng IV (Initialization Vector), giúp việc thử nghiệm từng khóa trở nên đơn giản và nhanh chóng hơn vì mỗi block được mã hóa độc lập
3. **Cấu trúc Padding:** AES yêu cầu dữ liệu đầu vào phải là bội số của 16 bytes. Khi giải mã bằng khóa sai, quá trình gỡ bỏ Padding (`unpad`) thường sẽ gây ra lỗi, đây là dấu hiệu tốt để nhận biết khóa sai khi Brute-force

## 4. **Exploitation Strategy (Hướng giải)**

### Bước 1: Xác định phạm vi Brute-force
Dựa vào gợi ý "around 1770242628", chúng ta thiết lập một vòng lặp xung quanh giá trị này (ví dụ: cộng/trừ 1000 giây) để tìm `timestamp` chính xác đã được dùng làm khóa

### Bước 2: Tái tạo quy trình tạo khóa
Với mỗi giá trị `t` trong vòng lặp:
1. Chuyển `t` thành chuỗi và băm bằng SHA256
2. Lấy 16 byte đầu tiên làm khóa AES

### Bước 3: Thử giải mã và kiểm tra
1. Sử dụng `AES.MODE_ECB` để giải mã `ciphertext`
2. Kiểm tra tính hợp lệ bằng cách:
   - Sử dụng hàm `unpad`. Nếu không lỗi, đó là ứng cử viên tiềm năng
   - Kiểm tra xem kết quả có chứa từ khóa `pico` hay không

## 5. **Solution Code Snippet**
```python
for offset in range(-100, 100):
    ts = 1770242628 + offset
    key = sha256(str(ts).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        dec = unpad(cipher.decrypt(ciphertext), 16)
        if b"pico" in dec:
            print(dec.decode())
    except:
        continue
```

FLAG: picoCTF{sa3S_sEc9t_9201873c}
-----
