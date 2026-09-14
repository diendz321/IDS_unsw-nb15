# Xây dựng hệ thống phát hiện xâm nhập mạng sử dụng DualNet trên Raspberry Pi 4

## 📖 Tổng quan
Dự án xây dựng một hệ thống phát hiện xâm nhập mạng (NIDS) sử dụng mô hình học sâu DualNet, được thiết kế và tối ưu hóa để triển khai trên thiết bị biên Raspberry Pi 4. Hệ thống phân tích lưu lượng mạng để nhận diện các hoạt động tấn công và tự động cung cấp thông tin cảnh báo cho người vận hành thông qua Dashboard và Email. Mô hình DualNet (kết hợp tích chập tách biệt chiều sâu - DSC, đơn vị hồi quy có cổng - GRU và cơ chế tự chú ý) được huấn luyện trên bộ dữ liệu UNSW-NB15 cho bài toán phân loại nhị phân.

## ✨ Tính năng chính
*   **Thu thập và trích xuất lưu lượng thời gian thực**: Sử dụng `tcpdump`, `Argus` và `Zeek` để thu thập và phân tích gói tin mạng theo các cửa sổ 15 giây, sau đó hợp nhất và trích xuất thành 39 đặc trưng mạng.
*   **Động cơ phát hiện bằng Deep Learning**: Nạp trực tiếp mô hình DualNet đã huấn luyện (`.keras`) và bộ tiền xử lý (`.joblib`) để suy diễn, gán nhãn dự đoán (Attack/Normal) trực tiếp trên thiết bị.
*   **Bảng điều khiển giám sát (Dashboard)**: Giao diện Web hiển thị thời gian thực kết nối với Firebase Realtime Database. Người quản trị có thể theo dõi luồng mạng, lọc theo IP nguồn/đích và nhận biết ngay các giao dịch mạng bị đánh dấu `ATTACK`.
*   **Cảnh báo tấn công qua Email**: Tích hợp luồng chạy nền (async) để tự động gửi thư báo cáo chi tiết về luồng mạng ngay khi hệ thống phát hiện hành vi xâm nhập.
*   **Đo lường hiệu suất hệ thống**: Cung cấp công cụ theo dõi lượng RAM tiêu thụ, phần trăm CPU và đo lường chi tiết thời gian suy diễn trung bình trên mỗi mẫu dữ liệu trong thời gian chạy.

## 📂 Cấu trúc dự án
*   `extract_features.py`: Tiền xử lý, chuẩn hóa khóa ghép 5 thành phần, hợp nhất dữ liệu từ Argus và Zeek, sau đó tính toán bộ đếm trên 100 kết nối gần nhất để xuất ra CSV.
*   `live_capture.sh`: Script Bash điều phối tác vụ thu thập gói tin trực tiếp trên giao diện mạng (`eth0`) và đẩy tệp PCAP qua tiến trình phân tích nền một cách bất đồng bộ.
*   `offline_process.sh`: Script kiểm thử hỗ trợ phân tích toàn bộ một tệp PCAP ngoại tuyến và bàn giao kết quả cho NIDS engine.
*   `nids_engine.py` / `nids_engine_1.py`: Động cơ NIDS chính phụ trách nạp mô hình, chạy Warm-up tránh độ trễ ban đầu, liên tục theo dõi tệp luồng mạng mới, dự đoán và đồng bộ cảnh báo.
*   `index.html`, `style.css`, `app.js`: Cấu trúc frontend cho giao diện giám sát có tích hợp Firebase Authentication và cơ chế chống lag giao diện bằng Batch Rendering.
*   Mã nguồn Jupyter (`Python 3`): Lưu trữ quy trình làm sạch dữ liệu, xử lý mất cân bằng phân lớp, chuẩn hóa `MinMaxScaler`, mã hóa `OneHotEncoder` và huấn luyện mạng phân tán qua nhiều GPU.

## ⚙️ Yêu cầu môi trường
*   **Phần cứng**: Máy Raspberry Pi 4 (có thể cấu hình làm Access Point) hoặc máy chủ Linux.
*   **Phần mềm & Hệ thống**: 
    *   Hệ điều hành Linux/Ubuntu.
    *   Python 3.x.
    *   Các phần mềm phân tích mạng lõi: `tcpdump`, `argus-client`, `Zeek`.
*   **Thư viện Python**: `tensorflow`, `pandas`, `numpy`, `joblib`, `scikit-learn`, `requests`, `psutil`.

## 🚀 Hướng dẫn Cài đặt & Vận hành

```bash
# BƯỚC 1: CHUẨN BỊ TỆP MÔI TRƯỜNG
# 1. Đặt mô hình AI (unsw_nids_dnn_model.keras) và bộ tiền xử lý (unsw_preprocessor.joblib) vào cùng thư mục với mã nguồn triển khai.
# 2. Cấu hình thông tin Email (SMTP) và khóa bí mật Firebase Realtime Database bên trong tệp nids_engine.py.

# BƯỚC 2: KHỞI ĐỘNG ĐỘNG CƠ PHÁT HIỆN (TERMINAL 1)
# Kích hoạt môi trường Python và khởi chạy động cơ dự đoán (Hệ thống sẽ chạy Warm-up trước khi sẵn sàng):
python3 nids_engine.py

# BƯỚC 3: THU THẬP VÀ XỬ LÝ LƯU LƯỢNG (TERMINAL 2)
# Khởi động quá trình phân tích luồng mạng bằng 1 trong 2 tùy chọn dưới đây:

# Tùy chọn A - Giám sát mạng trực tiếp (Real-time): Xoay vòng PCAP mỗi 15 giây và sinh file cho NIDS đọc.
sudo ./live_capture.sh

# Tùy chọn B - Thử nghiệm ngoại tuyến (Offline): Phân tích mạng từ tệp PCAP có sẵn.
sudo ./offline_process.sh /duong/dan/file_kiem_thu.pcap

# BƯỚC 4: GIÁM SÁT HỆ THỐNG TRÊN DASHBOARD
# 1. Mở tệp index.html trên trình duyệt web.
# 2. Đăng nhập bằng tài khoản quản trị (tạo trong Firebase Auth).
# 3. Theo dõi luồng dữ liệu, các cảnh báo ATTACK sẽ được tô đỏ và hệ thống sẽ tự động gửi email cho quản trị viên.
```

## ✍️ Tác giả & Bản quyền
*   **Nguyễn Văn Diện** - Khoa Điện tử Viễn thông, Trường Đại học Công nghệ - ĐHQGHN.