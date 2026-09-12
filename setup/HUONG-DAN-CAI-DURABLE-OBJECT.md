# Cài Durable Object — hướng dẫn từng bước

Dành cho người đã cài RSROLEPLAY bằng **Cách B** (dán code vào trang quản trị Cloudflare).

Bạn **không cần** cài gì vào máy, không cần biết lập trình. Mất khoảng 5 phút.

---

## Nó là gì, và vì sao cần

Câu trả lời dài của AI hay bị cắt ngang giữa chừng? Đó là vì Cloudflare chỉ cho mỗi lượt chạy **10 mili giây CPU**. Durable Object được **30 giây** và chạy tiếp cả khi bạn đóng tab — nên câu trả lời mới về đủ.

Trang quản trị Cloudflare không tạo được Durable Object (nó cần một thứ gọi là *migration*). Script dưới đây làm hộ bạn.

Nó **không sửa code và không đụng vào dữ liệu**: nó đọc đúng đoạn code đang chạy trên Worker của bạn, gửi lại y nguyên, chỉ thêm phần Durable Object vào.

---

## Làm theo thứ tự này

### 1. Mở Google Colab

Vào **https://colab.research.google.com** rồi đăng nhập bằng tài khoản Google.

Hiện ra một bảng hỏi mở file nào thì bấm **New notebook** (góc dưới bên phải). Nếu không thấy bảng đó, bấm menu **File → New notebook**.

Bạn sẽ thấy một ô trống có nút ▶ ở bên trái. Đó là chỗ để dán code.

### 2. Lấy code

Mở file [`colab-durable-object.py`](colab-durable-object.py) trong thư mục này.

Trên GitHub: bấm nút **Copy raw file** (biểu tượng hai tờ giấy chồng nhau, góc trên bên phải khung code). Nếu tải cả bộ về máy: mở file bằng Notepad, bấm `Ctrl + A` rồi `Ctrl + C`.

> ⚠️ Phải là file **`.py`**. Đừng chép file `.ipynb` — đó là định dạng của chính Colab, chép nội dung nó vào ô code sẽ chỉ hiện ra một đống dấu ngoặc.

### 3. Dán vào Colab rồi bấm ▶

Bấm vào ô trống trong Colab, dán (`Ctrl + V`), rồi bấm nút **▶** bên trái ô.

Lần đầu Colab sẽ hỏi kết nối máy chủ — cứ bấm đồng ý và chờ khoảng 15 giây.

### 4. Lấy token bằng nút cam

Dưới ô code sẽ hiện ra một bảng. Bấm nút cam **Mở trang tạo token ↗** — Cloudflare mở ở tab mới, thường đã tick sẵn đúng 3 quyền cần thiết.

Ở trang đó chỉ việc kéo xuống bấm **Continue to summary** → **Create Token** → **Copy**.

> Nếu trang mở ra mà chưa tick sẵn quyền nào, bảng trong Colab có in đúng 3 dòng cần tick, cứ chọn tay theo đó.

Token là một dãy chữ số dài và Cloudflare **chỉ hiện một lần** — chép xong hãy quay lại tab Colab.

### 5. Dán token, chọn Worker, bấm cài

1. Dán token vào ô **Dán token vào đây** rồi bấm **Kiểm tra token**. (Gõ vào không thấy chữ hiện lên là bình thường — ô này cố ý che.)
2. Nếu bạn có nhiều tài khoản hoặc nhiều Worker, hai ô chọn sẽ hiện ra — chọn đúng cái của bạn. Chỉ có một thì Colab tự chọn, không phải làm gì.
3. Bấm nút xanh **Cài Durable Object** rồi chờ vài giây.

Thấy khung xanh **✅ XONG!** là được. Trong đó có sẵn địa chỉ web của bạn để bấm vào mở thử, và một link để quay lại **xoá token** — nên xoá, token đã hết việc.

---

## Cách khác: mở thẳng file notebook

Nếu quen dùng Colab, bạn có thể tải [`colab-durable-object.ipynb`](colab-durable-object.ipynb) rồi vào Colab bấm **File → Upload notebook** và chọn file đó. Nội dung y hệt, chỉ khác là đã nằm sẵn trong ô code.

---

## Gặp trục trặc

| Thấy gì | Làm gì |
|---|---|
| Cả ô code toàn dấu `{` `}` và `"nbformat"` | Bạn đã chép nhầm file `.ipynb`. Chép lại file `.py`. |
| *Token này không dùng được* | Chép thiếu một đoạn, hoặc token đã bị xoá. Tạo token mới. |
| *Token này không thấy tài khoản nào* | Lúc tạo token thiếu dòng **Account Settings: Read**. Tạo lại cho đủ 3 quyền. |
| *Tài khoản này chưa có Worker nào* | Bạn chưa cài RSROLEPLAY lên Cloudflare. Làm bước đó trước. |
| *Code trên Worker này không có phần ChatStreamer* | Worker đang chạy bản code cũ. Vào Cloudflare → Worker của bạn → **Edit Code**, dán `worker.js` mới nhất vào, bấm **Deploy**, rồi chạy lại. |
| *Cloudflare không nhận bản cập nhật* | Đọc dòng **Cloudflare nói:** ngay bên dưới. Code trên Worker vẫn nguyên như cũ, sửa xong chạy lại được. |
| Chạy xong nhưng vẫn báo chưa thấy | Chờ một phút rồi bấm ▶ lần nữa. Cloudflare cần chút thời gian. |

Chạy lại bao nhiêu lần cũng không sao: nếu Durable Object đã có sẵn, script chỉ báo một dòng rồi dừng.

---

## Kiểm tra lại bằng mắt

Vào **dash.cloudflare.com** → **Workers & Pages** → chọn Worker của bạn → **Settings** → **Bindings**.

Phải thấy hai dòng:

| Tên | Loại |
|---|---|
| `DB` | D1 database |
| `STREAMER` | Durable Object |

Có đủ hai dòng đó là xong.
