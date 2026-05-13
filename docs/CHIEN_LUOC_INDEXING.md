# CHƯƠNG 3: THIẾT KẾ VÀ CÀI ĐẶT HỆ THỐNG

## 3.4. Chiến lược lập chỉ mục dữ liệu (Indexing Strategy)

Trong các hệ thống SIEM, việc thiết kế chiến lược lập chỉ mục (indexing) đóng vai trò quyết định đến hiệu suất ghi dữ liệu (ingestion rate) và tốc độ phản hồi của hệ thống giám sát. Dựa trên cấu hình thực tế của hệ thống và logic xử lý tại giao diện điều khiển, chúng tôi đã xây dựng chiến lược lập chỉ mục như sau:

### 3.4.1. Phân tích cấu hình và tính năng Real-time
Hệ thống sử dụng cơ chế **Daily Time-based Indexing** (phân tách chỉ mục theo ngày) kết hợp với các thiết lập tối ưu hóa truy vấn tức thời:

* **Tối ưu hóa khả năng hiển thị (Refresh Interval):** Chúng tôi thiết lập tham số `refresh_interval` ở mức **1 giây**. Lựa chọn này nhằm ưu tiên tối đa tính thời gian thực cho hệ thống. Dữ liệu sau khi được thu thập và xử lý qua Logstash chỉ mất 1 giây để sẵn sàng cho các truy vấn từ Dashboard, giúp chúng tôi phát hiện các dấu hiệu tấn công ngay lập tức.
* **Định nghĩa kiểu dữ liệu tường minh (Explicit Mapping):** Thay vì để hệ thống tự động nhận diện kiểu dữ liệu, chúng tôi định nghĩa chuẩn xác các trường quan trọng như `src_ip`, `dest_ip` là kiểu `ip`, và các trường phân loại là `keyword`. Điều này giúp tăng tốc độ tìm kiếm trên các dải mạng lớn và tiết kiệm tài nguyên bộ nhớ cho hệ thống.
* **Cấu hình tài nguyên Single-node:** Do triển khai trong môi trường thực nghiệm, hệ thống được thiết lập 1 shard và không sử dụng bản sao (0 replica). Cấu hình này giúp giảm thiểu các tài nguyên quản lý dư thừa, tập trung toàn bộ năng lực xử lý cho việc ghi và đọc dữ liệu trên một nút duy nhất.

### 3.4.2. Cơ chế đồng bộ hóa giữa Backend và Frontend
Để đảm bảo trải nghiệm người dùng tốt nhất mà không gây áp lực quá tải lên server, chúng tôi đã thiết lập sự phân cấp về tần suất cập nhật dữ liệu:

* **Tầng dữ liệu (Elasticsearch):** Hệ thống cập nhật dữ liệu mỗi **1 giây** để đảm bảo cơ sở dữ liệu luôn ở trạng thái mới nhất .
* **Tầng giám sát trực tiếp (Live Feed):** Chúng tôi sử dụng chu kỳ cập nhật **5 giây/lần** để hiển thị các dòng log mới nhất, giúp theo dõi sát sao các biến động an ninh theo thời gian thực mà vẫn đảm bảo độ mượt mà của giao diện.
* **Tầng thống kê (Dashboard):** Các biểu đồ tổng quát được thiết lập tự động vẽ lại sau mỗi **30 giây** . Việc duy trì chu kỳ này giúp giảm tải cho trình duyệt khi phải xử lý lại các phép tính toán phức tạp thường xuyên, đảm bảo tính ổn định cho toàn bộ giao diện giám sát.

### 3.4.3. Đánh giá và hướng cải tiến
Mặc dù cấu hình hiện tại đáp ứng rất tốt yêu cầu về tốc độ hiển thị và hiệu năng thực nghiệm, chúng tôi nhận thấy trong môi trường vận hành thực tế quy mô lớn cần xem xét các nâng cấp sau:

1. **Áp dụng Index Lifecycle Management (ILM):** Chuyển đổi sang cơ chế quản lý chỉ mục dựa trên kích thước thay vì chỉ dựa trên thời gian để tối ưu hóa dung lượng lưu trữ.
2. **Cấu hình High Availability:** Thiết lập thêm các bản sao dữ liệu (replicas) khi triển khai trên cụm máy chủ để đảm bảo an toàn dữ liệu và khả năng chịu lỗi.
3. **Dynamic Templates:** Xây dựng các khuôn mẫu động để tự động chuẩn hóa kiểu dữ liệu cho các trường phát sinh từ các nguồn log mới trong tương lai.