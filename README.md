# Cryptography-RSA

Bộ công cụ tương tác giúp khám phá mật mã RSA, các kỹ thuật phân tích mật mã kinh điển và những biện pháp phòng thủ cơ bản. Dự án cung cấp một máy chủ Flask với giao diện dashboard trình diễn các kiểu tấn công RSA phổ biến (Wiener, Hastad, chosen plaintext, chosen ciphertext, v.v.), tiện ích sinh khóa, ký số và mã hóa.

---

## Tính năng nổi bật

- Sinh khóa RSA 3072-bit kèm ghi log chi tiết để thuận tiện trình diễn.
- Dashboard web (Bootstrap + JavaScript thuần) giao tiếp với REST API.
- Thư viện các đòn tấn công RSA kinh điển: factorisation helpers, mô phỏng tấn công kênh kề thời gian, Hastad broadcast, Wiener small private exponent, oracle CCA/CPA.
- Tự động lưu trữ artefact: khóa PEM trong `keys/`, mẫu bản rõ/bản mã trong `data/`, nhật ký ứng dụng trong `server.log`.
- Tích hợp sẵn rate limiting, CORS và logging phòng thủ để thử nghiệm an toàn.

---

## Cấu trúc dự án

```
.
├── data/                    # Mẫu runtime (ciphertext/plaintext)
├── keys/                    # Cặp khóa PEM sinh trong phiên hiện tại
├── src/
│   ├── server.py            # Ứng dụng Flask & REST API
│   ├── rsa_cryptanalysis/   # Lõi RSA và các mô-đun tấn công
│   ├── static/              # JavaScript cho giao diện
│   └── templates/           # Template Jinja2 cho dashboard
├── requirements.txt         # Danh sách phụ thuộc
├── pytest.ini               # Cấu hình Pytest
└── README.md                # Tài liệu hướng dẫn
```

Hai thư mục `data/` và `keys/` được tạo trong lúc chạy và đã được `.gitignore`; có thể xóa để làm mới môi trường demo.

---

## Bắt đầu sử dụng

### 1. Yêu cầu hệ thống

- Python 3.12 (khuyến nghị) kèm `pip`
- PowerShell hoặc shell tương tự Unix
- (Tùy chọn) Công cụ môi trường ảo như `venv`

### 2. Cài đặt phụ thuộc

```powershell
git clone https://github.com/BlankBire/Cryptography-RSA.git
cd Cryptography-RSA
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Khởi chạy máy chủ

```powershell
python src/server.py
```

Dashboard sẽ xuất hiện tại `http://127.0.0.1:4444/` (đồng thời lắng nghe trên mạng LAN). Log hiển thị trên console và được lưu vào `server.log` ở thư mục gốc.

Dừng server bằng `Ctrl + C`. Mỗi lần khởi động lại, tiện ích RSA sẽ sinh khóa demo mới tự động.

---

## Hướng dẫn thao tác trên dashboard

1. **Get Public Key** – Nhấn “Get Public Key” để sinh và tải về cặp khóa. Tệp PEM được lưu trong `keys/`.
2. **Encrypt** – Nhập thông điệp và mã hóa bằng public key của server. Mỗi lần gọi:
   - ghi đè bản mã vào `data/ciphertext_samples.txt` (giữ nội dung rõ ràng),
   - nối thêm bản rõ vào `data/plaintext_samples.txt`,
   - ghi log xác thực vòng mã hóa/giải mã.
3. **Signing & Verification** – Lấy thông điệp đã ký từ server rồi kiểm tra chữ ký ở client.
4. **Attack Cards** – Thử từng đòn tấn công RSA khác nhau. Kết quả hiển thị trực tiếp và được ghi log kèm timestamp.

Các endpoint tốn tài nguyên có rate limit. Nếu bị giới hạn, hãy chờ một lúc hoặc khởi động lại server.

---

## Bảng REST API (tham khảo nhanh)

| Method | Endpoint                       | Mô tả                                                       |
| ------ | ------------------------------ | ----------------------------------------------------------- |
| POST   | `/api/generate-keys`           | Sinh cặp khóa 3072-bit và lưu PEM vào đĩa.                  |
| POST   | `/api/encrypt`                 | Mã hóa thông điệp bằng public key cung cấp.                 |
| POST   | `/api/sign`                    | Ký thông điệp bằng private key của server.                  |
| POST   | `/api/verify`                  | Xác minh chữ ký với public key hiện tại.                    |
| POST   | `/api/factorize`               | Chạy thử nhiều phương pháp phân tích nhân tử trên modulus.  |
| POST   | `/api/timing-attack`           | Mô phỏng tấn công kênh thời gian.                           |
| POST   | `/api/cca-attack`              | Mô phỏng oracle chosen ciphertext.                          |
| POST   | `/api/attacks/hastad`          | Thực hiện tấn công broadcast của Hastad.                    |
| POST   | `/api/wiener-attack`           | Thử tấn công Wiener với private exponent nhỏ.               |
| POST   | `/api/chosen-plaintext-attack` | Trình diễn oracle chosen plaintext lấy lại bản rõ mục tiêu. |

Mọi phản hồi đều kèm timestamp và thông điệp chi tiết; kiểm tra `server.log` để xem thêm phần truy vết.

---

## Kiểm thử

```powershell
pytest
```

Có thể thêm cờ `-k` (ví dụ `pytest -k wiener`) để chạy từng nhóm test. Khi viết test mới, đặt chúng trong thư mục `tests/` (tạo mới nếu chưa tồn tại) và tránh phụ thuộc trực tiếp vào dữ liệu phát sinh ở `data/` hoặc `keys/`.

---

## Hướng dẫn phát triển

- Giữ nguyên bố cục mô-đun trong `src/rsa_cryptanalysis/` khi bổ sung tấn công hoặc tiện ích mới.
- Sử dụng UTF-8 và không commit các tệp PEM/log sinh ra (đã nằm trong `.gitignore`).
- Cập nhật `requirements.txt` khi thêm thư viện; khóa phiên bản nhỏ để bản demo luôn ổn định.
- Viết docstring và log rõ ràng - quá trình mô phỏng tấn công khá phức tạp nếu thiếu ngữ cảnh.

Nếu bạn có ý tưởng cho các đòn tấn công RSA mới, cải tiến giao diện hay tối ưu hiệu năng, hãy mở issue hoặc gửi pull request!
