## 1. **Challenge Description**

<img width="908" height="563" alt="image" src="https://github.com/user-attachments/assets/a09a7f82-8d81-4eaa-a95f-5a3f249300e9" />

## 2. **Initial Enumeration**
Kiểm tra các tệp tin được cung cấp bằng lệnh `file` để xác định định dạng:
```bash
file *
```
- `flag.enc`: Dữ liệu thô (binary data), khả năng cao là bản mã RSA
- `image.jpg`: Tệp ảnh JPEG. Đáng chú ý, trong phần metadata có một đoạn **comment** chứa chuỗi Hex dài: `2d2d2d2d2d424547494e2050524956415445204b45592d...`

## 3. **Steganography Analysis**
Dựa vào gợi ý "careless with the private key", chúng ta phân tích đoạn Hex trong comment của ảnh
Chuỗi `2d2d2d2d2d424547494e...` khi chuyển sang ASCII có dạng:
- `2d2d2d2d2d` -> `-----`
- `424547494e` -> `BEGIN`
- `2050524956415445204b4559` -> ` PRIVATE KEY`

Đây chính là một **RSA Private Key** được giấu dưới dạng Hex trong Metadata (Comment field)

## 4. **Key Recovery**
Sử dụng `exiftool` kết hợp với `python` để trích xuất toàn bộ chuỗi Hex và chuyển đổi ngược lại thành định dạng tệp `.pem`:

```bash
exiftool -Comment image.jpg | cut -d: -f2- | xargs | python3 -c "import sys; print(bytes.fromhex(sys.stdin.read().strip()).decode())" > private.pem
```

Kiểm tra tệp `private.pem`:
```bash
cat private.pem
```
Kết quả thu được một RSA Private Key hợp lệ bắt đầu bằng `-----BEGIN PRIVATE KEY-----`

## 5. **RSA Decryption**
Sử dụng công cụ `openssl` với Private Key vừa khôi phục để giải mã tệp `flag.enc`. Vì RSA thường sử dụng các công cụ xử lý tệp tin mã hóa trực tiếp, ta dùng lệnh `pkeyutl`:

```bash
openssl pkeyutl -decrypt -inkey private.pem -in flag.enc
```

**Kết quả:**
```bash
picoCTF{rs4_k3y_1n_1mg_ce170c3d}
```

**FLAG:** `picoCTF{rs4_k3y_1n_1mg_ce170c3d}`
-------
