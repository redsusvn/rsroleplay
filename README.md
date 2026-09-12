# 🚀 RSROLEPLAY Engine

Nền tảng roleplay với AI, chạy hoàn toàn serverless trên **Cloudflare Workers**, **Cloudflare D1** và **Durable Objects**. Tự dựng một chỗ roleplay riêng — mỗi nhân vật một diện mạo, câu trả lời không mất kể cả khi đóng tab, giao diện đổi được tận gốc — mà không tốn tiền máy chủ.

*A lightning-fast, fully serverless AI roleplay platform powered by **Cloudflare Workers**, **Cloudflare D1** and **Durable Objects**. Build your own private roleplay hub at zero hosting cost — or just use it as your everyday AI chat client.*

**Làm bởi / Built by [@redsus.vn](https://miku.us.kg) · TikTok: [@redsusvn](https://www.tiktok.com/@redsusvn)**

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/redsusvn/rsroleplay)

Bấm nút trên là Cloudflare tự tạo Worker, cơ sở dữ liệu và Durable Object rồi cài đặt hết — không cần cài gì vào máy, không phải điền khoá nào.
*One click. Cloudflare creates the Worker, the database and the Durable Object for you — nothing to install, nothing to fill in.*

📖 [Tiếng Việt](#-tiếng-việt) · [English](#-english)

---

## 🎬 Video

### Hướng dẫn cài đặt / Installation guide

[![Hướng dẫn cách cài source RSROLEPLAY Chat Bot AI không giới hạn](https://img.youtube.com/vi/6k_mkhUTu0k/maxresdefault.jpg)](https://www.youtube.com/watch?v=6k_mkhUTu0k)

▶️ [Xem trên YouTube / Watch on YouTube](https://www.youtube.com/watch?v=6k_mkhUTu0k)

### Giới thiệu / Showcase

[![Giới thiệu Website Roleplay Selfhost thế hệ mới - RSRoleplay](https://img.youtube.com/vi/-shmKdaQkTI/maxresdefault.jpg)](https://www.youtube.com/watch?v=-shmKdaQkTI)

▶️ [Xem trên YouTube / Watch on YouTube](https://www.youtube.com/watch?v=-shmKdaQkTI)

---

# 🇻🇳 Tiếng Việt

## ✨ Tính năng

### Câu trả lời không bị mất
- **⚡ 100% serverless:** Chạy trọn trên hạ tầng biên của Cloudflare (Workers + D1 + Durable Objects). Không VPS, không backend. Mọi thứ nằm gọn trong gói **Free**.
- **🛡️ Trả lời không thất lạc:** Tin của bạn được lưu *trước khi* gọi AI, còn câu trả lời được ghi vào database ngay trong lúc đang chảy về — lúc đầu vài giây một lần, rồi thưa dần (tối đa 25 giây), nên một câu trả lời dài bốn phút vẫn nằm trong giới hạn database của gói Free. Đóng tab, mất sóng, chuyển app — quay lại là câu trả lời vẫn ở đó (hoặc vẫn đang chạy tiếp, và trang tự theo dõi).
- **🔁 Tự nối lại:** Nhà cung cấp AI rớt kết nối giữa chừng thì máy chủ tự kết nối lại, bảo mô hình viết tiếp đúng từ chỗ đứt, rồi ghép hai nửa lại.
- **🧠 Mô hình biết suy luận:** Hỗ trợ sẵn các mô hình reasoning (DeepSeek R1, Qwen3, Gemma/Gemini `<thought>`) với khối **Quá trình suy luận** mở ra xem được.
- **🔌 Nhiều nhà cung cấp:** Groq, OpenRouter, Mistral, Cloudflare AI, Gemini, hoặc bất kỳ endpoint tương thích OpenAI nào. Nút **Chọn** liệt kê sẵn mô hình của nhà cung cấp để bạn khỏi phải nhớ id, còn nút **Thử** kiểm tra endpoint trước khi bạn tin vào nó.
- **🎛️ Bộ cài sẵn cho AI:** Mặc định, Bay bổng, Chính xác — hoặc Tuỳ chỉnh, với nhiệt độ, top-p, top-k và các mức phạt lặp.

### Roleplay
- **🎭 Nhân vật:** Mỗi nhân vật có ảnh đại diện (link ảnh, ảnh nhúng, emoji hoặc hai chữ cái), mô tả, lời nhắc hệ thống, lời chào, và *vai của bạn* — bạn là ai trong câu chuyện đó.
- **🔀 Vuốt đổi bản:** Tạo lại câu trả lời rồi vuốt qua lại giữa các bản, như app gốc.
- **📌 Bảng ghi nhớ:** Ghim sự kiện, luật lệ, lời hứa vào một đoạn chat để AI không bao giờ quên.
- **📚 Tự tóm tắt:** Tin nhắn cũ được tóm tắt ngầm để câu chuyện dài vẫn nằm trong cửa sổ ngữ cảnh của mô hình.
- **🔄 Nhập từ Character.AI / xuất TXT:** Thả vào file `.txt` xuất từ Character.AI, hoặc tải đoạn chat bất kỳ về dạng thẻ `{user}` / `{bot}`.

### Tuỳ biến theo ý bạn
- **🧩 10 bố cục** — không phải đổi màu, mà là 10 kiểu giao diện khác nhau: Studio, Rail, Trio, Zen, Deck, Console, Ledger, Split, Canvas, Tiles.
- **🎨 6 bộ màu nền** (Graphite, Aurora, Vellum, Clay, Void, Sherbet) × màu chính tuỳ chọn. Cả bảng màu được dựng lại quanh màu bạn chọn, cho cả sáng lẫn tối.
- **💬 240 mẫu bubble** chia 16 nhóm — kinh điển, chuyển sắc, neumorphism, terminal retro, hiệu ứng "sống", hoạ tiết emoji, phong cảnh, tai và chân thú… Cho AI và bạn hai mẫu khác nhau, đổi màu bất kỳ mẫu nào, chỉnh độ trong, và bật **Giữ chữ dễ đọc** để chữ tự tối lại khi mẫu phía sau quá sáng.
- **🫧 Kính mờ:** Khúc xạ thật — thanh bên, thanh tiêu đề, bubble và các nút đều bẻ cong hình nền phía sau — kèm thanh chỉnh độ mờ. Tự tắt khi hệ điều hành yêu cầu giảm hiệu ứng trong suốt.
- **🖼️ Hình nền:** Một tấm ảnh, một link video (`.mp4`, `.webm`, `.mov` phát tắt tiếng và lặp lại), hoặc file ngay trong máy bạn (tối đa 120 MB, chỉ nằm ở máy đó). Có chỉnh làm tối, làm nhoè và mức lộ nền.
- **🖱️ Con trỏ riêng:** Con trỏ có sẵn, link trang con trỏ (ví dụ rw-designer.com), link ảnh `.png` / `.gif` / `.cur` trực tiếp, hoặc tự tải lên — chỉnh được điểm bấm và kích thước.
- **👥 Mỗi nhân vật một diện mạo:** Mọi cài đặt giao diện đều áp dụng được cho **toàn bộ ứng dụng**, cho **một nhân vật**, hoặc cho **một đoạn chat**. Mở chat của nhân vật nào là bubble, màu và hình nền đổi theo nhân vật đó.
- **☁️ Giao diện đi theo tài khoản:** Cài đặt giao diện lưu trong database, nên máy thứ hai đăng nhập vào là có ngay. Chỉ hình nền chọn từ file trong máy là nằm lại máy đó.
- **🗂️ Panel gắn cạnh:** Ở bố cục Rail, Trio và Split (màn hình từ 1024 px trở lên), các panel như Nhân vật, Kết nối API, Trí nhớ mở ra ở cột bên thay vì popup. **Đoạn chat hiện tại** gấp cột đó lại, trả toàn bộ bề ngang cho cuộc trò chuyện.

### Riêng tư và an toàn
- **🔐 Đăng nhập hai lớp:** Dùng được với mọi app xác thực (Google Authenticator, Aegis, 1Password…) kèm mã khôi phục dùng một lần. Xem bảng khoá bên dưới — nó nghiêm khắc có chủ đích.
- **🧱 Chưa đăng nhập thì không lộ gì:** Mọi endpoint có dữ liệu đều đòi phiên đăng nhập. Chưa đăng nhập thì chỉ thấy form đăng nhập — và sai mật khẩu vài lần là IP bị khoá một lúc.
- **🧼 Làm sạch nội dung:** Mọi thứ AI viết ra đều được lọc trước khi hiển thị, và mọi phản hồi đều kèm Content Security Policy cùng các header bảo mật.

### Trên điện thoại
- **📲 Cài được như app:** Thêm vào màn hình chính trên Android hay iPhone là mở ra như app riêng, có icon riêng. Cố ý không dùng service worker, nên bản đã cài không bao giờ giữ lại bản sao offline của đoạn chat.
- **📱 Làm cho ngón tay:** Vùng chạm 44 px, hộp thoại luôn vừa màn hình thật (tính cả thanh địa chỉ), và hiệu ứng kính được gỡ khỏi những thứ cuộn, nên chat dài vẫn mượt.

---

## 🛠️ Hướng dẫn cài đặt

Có ba cách. **Nhanh nhất là bấm nút ngay dưới đây** — Cloudflare làm hết. Cách A dành cho ai muốn tự chủ hoàn toàn từ máy mình. Cách B dành cho ai không muốn cài gì vào máy và làm mọi thứ trên trang quản trị.

### Cần chuẩn bị
- Một tài khoản [Cloudflare](https://dash.cloudflare.com) (gói Free là đủ).
- Một API Key của nhà cung cấp AI (ví dụ [GroqCloud](https://console.groq.com/home)).
- Riêng Cách A: máy có cài [Node.js](https://nodejs.org) (bản LTS).

---

### ⚡ Cách nhanh nhất — bấm một nút (khoảng 2 phút)

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/redsusvn/rsroleplay)

Bấm vào đó rồi đăng nhập Cloudflare. Cloudflare sẽ tự:

1. sao chép mã nguồn về tài khoản GitHub của bạn,
2. tạo một **cơ sở dữ liệu D1** mới,
3. tạo **Durable Object** `ChatStreamer` (thứ giúp câu trả lời dài không bị cắt),
4. deploy Worker và đưa bạn đường dẫn để mở.

Không phải điền khoá bí mật nào — cả ứng dụng chỉ cần hai thứ ở trên. Mở đường dẫn vừa nhận được là tới ngay màn hình tạo tài khoản quản trị (xem [Lần đầu chạy](#lần-đầu-chạy--tài-khoản-quản-trị)).

Về sau muốn cập nhật thì vào bản sao repo của mình trên GitHub, thay `worker.js` bằng bản mới rồi commit — Cloudflare tự deploy lại.

> Bảng biểu trong cơ sở dữ liệu do chính ứng dụng tạo ở lần chạy đầu, nên không có bước migration nào phải chạy tay.

---

### Cách A — Tự deploy bằng `wrangler` (khoảng 10 phút)

> **Vì sao quan trọng:** một Worker thường trên gói Free chỉ được **10 mili giây CPU mỗi request**, mà một câu trả lời dài thì vượt quá — Cloudflare cắt ngang giữa chừng. Nên engine này chạy mỗi câu trả lời bên trong một **Durable Object**, thứ được **30 giây CPU** và chạy tiếp cả sau khi bạn đóng trang. Durable Object chỉ sinh ra được bằng một *migration*, mà trang quản trị không chạy được — `wrangler` thì có.

> **💡 Đường tắt — trình cài đặt.** Thay cho Bước 3–5 bên dưới, bạn có thể chạy
> ```bash
> node setup/server.mjs
> ```
> rồi mở **http://127.0.0.1:8788**. Nó dẫn bạn tạo API token (nói rõ phải tick quyền nào), chọn tài khoản, đặt tên Worker và tạo database, rồi viết sẵn file `wrangler.toml` điền đủ id. Bước `npx wrangler deploy` (Bước 6) vẫn do bạn chạy. Nó là một file duy nhất không phụ thuộc gói nào, chỉ nghe trên máy bạn, và token không bao giờ chạm vào ổ đĩa.

#### Bước 1: Lấy file
Tải repository này về (**Code → Download ZIP**) rồi giải nén. Bạn cần hai file nằm cùng thư mục: `worker.js` và `wrangler.toml`.

#### Bước 2: Mở terminal ngay thư mục đó
Windows: mở thư mục trong Explorer, bấm vào thanh địa chỉ, gõ `powershell`, Enter.
macOS/Linux: mở Terminal rồi `cd` vào thư mục.

#### Bước 3: Đăng nhập Cloudflare
```bash
npx wrangler login
```
Lần đầu nó hỏi cài wrangler — gõ `y`. Một trang Cloudflare mở ra trong trình duyệt: bấm **Allow**.

#### Bước 4: Tạo database
```bash
npx wrangler d1 create rsroleplay-db
```
Kết quả in ra có dòng `database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`. Chép cái UUID đó lại.

#### Bước 5: Sửa `wrangler.toml`
Mở `wrangler.toml` bằng trình soạn thảo bất kỳ và sửa đúng ba dòng:
```toml
name = "myownchatplatform"          # tên Worker, cũng là tên trong địa chỉ web
database_name = "rsroleplay-db"     # tên bạn đặt ở Bước 4
database_id = "DÁN-UUID-Ở-BƯỚC-4"
```
Phần còn lại giữ nguyên — nó đã khai báo sẵn binding `DB`, Durable Object `STREAMER` cùng migration của nó, lịch dọn dẹp hằng ngày và Smart Placement.

#### Bước 6: Deploy
```bash
npx wrangler deploy
```
Chạy xong phải thấy đủ hai binding:
```
env.STREAMER (ChatStreamer)      Durable Object
env.DB (rsroleplay-db)           D1 Database
```
kèm địa chỉ của bạn: `https://myownchatplatform.<subdomain-của-bạn>.workers.dev`.

Đi tiếp xuống phần **Lần đầu chạy** bên dưới.

---

### Cách B — Chỉ dùng trang quản trị (không cần terminal)

#### Bước 1: Tạo Worker
1. Đăng nhập trang quản trị Cloudflare.
2. Thanh bên trái, vào **Workers & Pages**.
3. Bấm **Create** → **Create Worker**.
4. Đặt tên (ví dụ `myownchatplatform`) rồi bấm **Deploy**.

#### Bước 2: Dán code vào
1. Deploy xong, bấm **Edit Code** trên Worker vừa tạo.
2. Xoá sạch code mẫu trong `worker.js`.
3. Chép toàn bộ nội dung `worker.js` của repository này rồi dán vào.
4. Bấm **Deploy** ở góc trên bên phải.

#### Bước 3: Hoàn tất bằng Colab (database + Durable Object)

Lúc này Worker đã có code nhưng chưa có database và chưa có Durable Object. Một script lo cả hai:

**[▶ Mở notebook cài đặt trên Google Colab](https://colab.research.google.com/drive/1TGZKllJQHez8J1ZaQEiOqyWNTTalenwQ?usp=sharing)** — hoặc tự chép [`setup/colab-durable-object.py`](setup/colab-durable-object.py) vào một notebook trống.

Bấm nút chạy. Bảng hiện ra có một nút mở thẳng trang tạo token của Cloudflare với quyền đã tick sẵn; dán token về, chọn Worker, bấm **Cài đặt**. Nó sẽ:

- tạo database D1 (hoặc nối database bạn đã có) vào binding tên `DB`, và
- cài **Durable Object** `ChatStreamer` — đúng cái mà trang quản trị không làm được, vì nó cần một *migration*.

Script đọc chính đoạn code đang chạy trên Worker rồi gửi lại y nguyên, nên thứ bạn dán ở Bước 2 không bị đụng tới. Token chỉ nằm trong phiên Colab của bạn, chỉ gửi tới `api.cloudflare.com`, và cuối cùng script nhắc bạn xoá nó đi.

Hướng dẫn từng bước cho người chưa từng mở Colab: [`setup/HUONG-DAN-CAI-DURABLE-OBJECT.md`](setup/HUONG-DAN-CAI-DURABLE-OBJECT.md).

<details>
<summary>Thích tự bấm trong trang quản trị? (chỉ được database, không có Durable Object)</summary>

1. Thanh bên Cloudflare, mở **Storage & databases** → **D1 SQL database** → **Create Database**. Đặt tên `rsroleplay-db`.
2. Vào **Workers & Pages**, mở Worker của bạn, rồi **Settings** → **Bindings** → **Add Binding** → **D1 database**.
3. **Variable name:** gõ đúng `DB` *(viết hoa hết)*. **D1 database:** chọn cái vừa tạo. Lưu lại.

Cách này chạy được app, nhưng chưa có Durable Object — xem lưu ý ngay dưới.
</details>

> **Khi chưa có Durable Object:** câu trả lời được sinh trong hạn mức 10 mili giây CPU của Worker. Câu ngắn và vừa thì không sao; câu thật dài có thể bị Cloudflare cắt ("Worker exceeded CPU time limit" trong log). Phần đã về vẫn được lưu và bạn bấm **Thử lại** được. Chạy script Colab ở trên là xong, hoặc chuyển sang Cách A bất cứ lúc nào: cài Node.js, điền tên Worker và tên/ID database hiện có vào `wrangler.toml` (ID nằm ở trang database D1), rồi chạy `npx wrangler login` và `npx wrangler deploy`. Đoạn chat vẫn còn nguyên — vẫn là database đó.

---

### Lần đầu chạy & tài khoản quản trị
1. Mở địa chỉ `.workers.dev` của Worker trong trình duyệt.
2. Màn hình Cài đặt lần đầu hiện ra.
3. Nhập tên đăng nhập và mật khẩu quản trị bạn muốn.
   > *Lưu ý: bản cài riêng này chỉ tạo được MỘT tài khoản. Giữ kỹ thông tin đăng nhập!*

### Nối AI vào (Kết nối API)
1. Đăng nhập vào bản RSROLEPLAY của bạn.
2. Bấm **Kết nối API** ở thanh bên trái (hoặc dấu **+** cạnh nút đóng).
3. Bấm **+ Thêm kết nối**.
4. Chọn nhà cung cấp (ví dụ `Groq`), dán API Key, rồi nhập id mô hình — hoặc bấm **Chọn** để lấy từ danh sách của nhà cung cấp (ví dụ `llama-3.3-70b-versatile`).
5. Tick ô **Đặt làm mặc định** rồi bấm **Lưu khoá**. Bấm **Thử** trên kết nối đó để chắc chắn nó trả lời được.

### Tên mô hình
- Mô hình chat: `google/gemma-4-26b-a4b-it`
- Mô hình tóm tắt: `llama-3.3-70b-versatile`

### Mô hình nên dùng
- OpenRouter: `nvidia/nemotron-3-super-120b-a12b:free`
- Gemini: `gemma-4-26b-a4b-it` và `gemma-4-31b-it`, cả hai đều chạy tốt.

🎉 **Xong!** Giờ vào "Đoạn chat hiện tại" và bắt đầu nói chuyện với AI của bạn.

---

## 🔐 Đăng nhập hai lớp

Bật ở **Cài đặt tài khoản → Xác thực hai lớp**: quét mã QR bằng app xác thực, nhập mã để xác nhận, và **lưu lại các mã khôi phục nó hiện ra** — mỗi mã dùng được một lần, và đó là đường vào duy nhất nếu bạn mất điện thoại.

Cơ chế khoá nghiêm khắc có chủ đích:

| Số lần sai | Hậu quả |
|---|---|
| 3 | chờ **10 phút** |
| sai thêm 1 | chờ **30 phút** |
| sai thêm 1 | chờ **1 tiếng** |
| sai thêm 1 | **khoá vĩnh viễn** — tên đăng nhập và mật khẩu bị thay bằng ký tự ngẫu nhiên |

Trang đăng nhập không bao giờ nói bạn đang ở mức nào — sai mã thì chỉ trả lời *"Vui lòng thử lại."* Nên đừng đoán: dùng mã khôi phục.

Nếu lỡ dính, đoạn chat và khoá API của bạn vẫn nguyên vẹn. Xoá tài khoản bị khoá bằng dòng lệnh rồi cài lại — và làm luôn một mạch, vì trang sẽ mời cài đặt lần đầu cho bất kỳ ai mở nó trước:
```bash
npx wrangler d1 execute rsroleplay-db --remote --command "DELETE FROM users; DELETE FROM user_sessions"
```

---

## 🎨 Tuỳ biến giao diện

Mọi thứ nằm trong **Giao diện** ở thanh bên:

- **Bố cục** — chọn một trong 10 kiểu giao diện.
- **Tuỳ chọn** — các lựa chọn riêng của bố cục bạn vừa chọn.
- **Màu** — bộ màu nền và màu chính; mọi thứ được dựng lại quanh nó. (Sáng hay tối: **Chuyển sáng/tối** ở thanh bên.)
- **Bubble** — duyệt 240 mẫu, cho phía AI, phía bạn, hoặc cả hai.
- **Tinh chỉnh bubble** — đổi màu mẫu đã chọn, chỉnh độ trong, đổi emoji của mẫu hoạ tiết emoji, bật tắt *Giữ chữ dễ đọc*, *Viền sau chữ* và phông riêng của mẫu.
- **Khác** — kính mờ, hình nền, con trỏ.

Dòng **Áp dụng cho** ở đầu panel quyết định thay đổi rơi vào đâu: **Toàn bộ ứng dụng**, **nhân vật này** hay **đoạn chat này**. Đặt giao diện ở mức nhân vật chính là cách mỗi nhân vật có bubble, màu và hình nền riêng — đổi chat là cả giao diện đổi theo.

---

## 🎞️ Nội dung demo

Muốn xem nó sống động trước khi tự viết chữ nào? File `demo/seed.sql` thêm tám nhân vật tự nghĩ, có ảnh chân dung, mẫu bubble và hình nền riêng, mỗi nhân vật kèm một đoạn hội thoại hoàn chỉnh — có cả bản vuốt đổi, khối suy luận, ghim bảng ghi nhớ và bản tóm tắt trí nhớ.

```bash
npx wrangler d1 execute rsroleplay-db --remote --file demo/seed.sql
```

Thay `--remote` bằng `--local` để thử trên `wrangler dev` trước. Muốn gỡ ra — và chỉ gỡ đúng phần đó — chạy lại lệnh trên với `demo/unseed.sql`. Nhân vật, đoạn chat và khoá của bạn không bị đụng tới: mọi dòng dữ liệu demo đều có id bắt đầu bằng `demo-`. Thứ duy nhất nó thêm vào phần cài đặt là giao diện riêng cho từng nhân vật demo, và `unseed.sql` cũng gỡ luôn phần đó.

*Ảnh chân dung và hình nền lấy từ [Pixabay](https://pixabay.com) (giấy phép Pixabay Content License). Ảnh chân dung được nhúng thẳng vào database; hình nền tải từ máy chủ Pixabay.*

---

## ⬆️ Cập nhật bản đã cài

Đoạn chat, nhân vật, khoá API và giao diện của bạn nằm trong D1 và được giữ nguyên qua các lần cập nhật. Cấu trúc database tự nâng cấp ở request đầu tiên sau khi cập nhật.

- **Cài bằng Cách A:** tải `worker.js` mới (và `wrangler.toml` nếu có đổi) vào thư mục của bạn, giữ nguyên ba dòng bạn đã sửa, chạy `npx wrangler deploy`.
- **Cài bằng Cách B:** mở Worker → **Edit Code**, thay toàn bộ bằng `worker.js` mới, bấm **Deploy**. Các binding được giữ nguyên.

Cập nhật xong chỉ cần tải lại trang — bản mới tự được nhận.

---

## 💡 Mẹo dùng

### Nhập từ Character.AI
1. Dùng tiện ích xuất lịch sử C.AI để lấy file `.txt` của đoạn chat.
2. Trong RSROLEPLAY Engine, bấm **Đồng bộ dữ liệu**.
3. Kéo thả file `.txt` vào ô "Nhập đoạn chat".
4. **Mẹo:** Nhờ Google Gemini tóm tắt lịch sử C.AI thành "Nhân vật" và "Lời nhắc hệ thống" có cấu trúc, để bot cư xử đúng như trước!

### Lời nhắc tóm tắt đoạn chat

Giữ nguyên tiếng Anh — đây là lời nhắc gửi cho AI, không phải chữ để người đọc:

```
### ROLE: Professional Narrative Analyst and Roleplay Architect
### TASK: Analyze the provided chat history to create a comprehensive "Story Bible." 
Your goal is to extract every essential data point, nuance, and plot thread to ensure the conversation can be resumed with 100% consistency. You must condense the history into a structured, high-density briefing for a future AI model.
---
### OUTPUT FORMAT
Follow this structure EXACTLY. Use the headers provided.
{PROMPT AND INFORMATION}
[BOT CHARACTER INFO]
* Name: 
* Personality & Core Traits: (A deep dive into their psyche, temperament, and hidden layers)
* Backstory/Lore: (History and secrets revealed during the chat)
* Physical Description: (Appearance, unique features, current attire)
[USER INFO]
* Name/Role: 
* Character Traits: 
* Current Motivation: (What is the user character currently trying to achieve?)
[CONVERSATION & NARRATIVE STYLE]
* Chatting Style: (e.g., Casual, formal, average length of responses, use of OOC)
* Bot Talking Style: (Vocabulary choices, accents, stutters, specific sentence structures, or catchphrases)
* Narrative Style: (Detailed description of the "Narrator" voice—e.g., poetic, gritty, third-person limited, first-person, focusing on internal monologue vs. external action)
{CHAT HISTORY}
[THE CHRONOLOGICAL TIMELINE]
Provide a detailed, bulleted summary of the story from the first message to the current moment:
* Major Plot Points: (Key events that drove the story forward)
* Emotional Milestones: (Shifts in the relationship dynamics, e.g., trust built, betrayal, romance)
* Key Revelations: (Facts or lore uncovered during the roleplay)
* Current Location/Context: (Exactly where the characters are, the time of day, and the immediate situation)
{SPECIFIC REQUIREMENT FOR CHAT}
[CONTINUATION DIRECTIVES]
* Storytelling Quality: (Analyze what made the history successful and instruct the AI on how to maintain it—e.g., "prioritize sensory details," "maintain slow-burn tension," or "focus on psychological realism")
* The "Vibe" to Maintain: (The specific atmosphere—e.g., Noir, Whimsical, Gothic Horror, High-Fantasy)
* Specific Constraints: (Operational rules based on the history—e.g., "Never speak for the user," "Always put internal thoughts in italics," "Keep responses under 3 paragraphs")
* Immediate Next Goal: (The specific focus for the very next response to maintain the current momentum)
---
### INPUT DATA: CHAT HISTORY BEGINS BELOW
[PASTE YOUR CHAT HISTORY HERE]
```

### Tối ưu trí nhớ
Nếu bot bắt đầu đãng trí, vào **Quy tắc ghi nhớ**. Chỉnh ngưỡng `Số tin nhắn đem tóm tắt` cho hợp với cửa sổ ngữ cảnh của mô hình bạn đang dùng.

### Cho mỗi nhân vật một khuôn mặt
Ô **Ảnh đại diện** của nhân vật nhận link ảnh, ảnh nhúng (`data:image/png`, `jpeg`, `webp` hoặc `gif`), emoji, hoặc hai chữ cái. Ảnh nhúng đi theo nhân vật và không bao giờ hỏng vì một máy chủ ảnh nào đó sập.

---

## ❓ Xử lý sự cố

- **"D1 database binding 'DB' not found"** — thiếu binding `DB`. Cách B: chạy lại script Colab, hoặc làm lại phần nối database. Cách A: kiểm tra `database_name` / `database_id` trong `wrangler.toml` rồi deploy lại (wrangler thay toàn bộ binding bằng đúng những gì ghi trong file đó).
- **Câu trả lời dài dừng giữa chừng / "Worker exceeded CPU time limit" trong Observability** — bạn đang chạy mà không có Durable Object. Chạy script Colab ở Cách B, hoặc chuyển sang Cách A.
- **Bubble báo "Không có câu trả lời nào được tạo — tin nhắn của bạn vẫn được lưu"** — nhà cung cấp AI lỗi. Tin của bạn vẫn còn; bấm **Thử lại**. Kiểm tra kết nối trong **Kết nối API** bằng nút **Thử**.
- **Câu trả lời hiện ra một cục thay vì chảy dần** — một tiện ích chặn quảng cáo hoặc bảo vệ riêng tư đang giữ luồng lại cho tới khi xong. Thêm địa chỉ Worker của bạn vào danh sách cho phép của nó.
- **Giao diện không theo sang máy khác** — nó được kéo về lúc đăng nhập, nên tải lại trang một lần ở máy kia. Riêng hình nền chọn từ file trong máy thì nằm lại máy đó.
- **Ảnh đại diện hiện hai chữ cái thay vì ảnh** — link phải bắt đầu bằng `http`, hoặc là ảnh nhúng dạng `png` / `jpeg` / `webp` / `gif`. SVG không được nhận.
- **Bị khoá vì xác thực hai lớp** — chờ hết thời gian theo bảng ở trên, hoặc dùng mã khôi phục. Sau lần sai cuối cùng thì tài khoản bị khoá vĩnh viễn, nên đừng đoán — cách xử lý nằm ở mục Đăng nhập hai lớp phía trên.
- **Durable Object nằm ở đâu?** — Trang quản trị → **Workers & Pages → Durable Objects** phải liệt kê `ChatStreamer`, và tab **Bindings** của Worker phải hiện `STREAMER`.

---

# 🇬🇧 English

## ✨ Features

### Replies you can rely on
- **⚡ 100% Serverless:** Runs entirely on Cloudflare's Edge (Workers + D1 + Durable Objects). No VPS, no backend. Everything fits in the **Free** plan.
- **🛡️ Replies that can't get lost:** Your message is saved *before* the AI is called, and the reply is written to the database while it streams — every couple of seconds at first, then further apart (never more than 25 s), so even a four-minute reply stays inside the Free plan's database limit. Close the tab, lose signal, switch apps — when you come back the reply is there (or still growing, and the page follows it live).
- **🔁 Auto-resume:** If the AI provider drops the connection mid-reply, the server reconnects and asks the model to continue from exactly where it stopped, stitching the halves together.
- **🧠 Thinking models:** Native support for reasoning models (DeepSeek R1, Qwen3, Gemma/Gemini `<thought>` output) with an expandable **Thought Process** block.
- **🔌 Multi-provider:** Groq, OpenRouter, Mistral, Cloudflare AI, Gemini, or any OpenAI-compatible endpoint. **Browse** lists a provider's models so you don't have to type IDs, and **Test** checks an endpoint before you rely on it.
- **🎛️ Generation presets:** Default, Creative, Precise — or Custom, with temperature, top-p, top-k and presence / frequency / repetition penalties.

### Roleplay
- **🎭 Characters:** Each persona has a portrait (image link, inline image, emoji or initials), a description, a system prompt, a greeting, and a *user persona* — who **you** are in that story.
- **🔀 Swipe variants:** Regenerate a reply and swipe between the versions, like a native app.
- **📌 Sketchboard:** Pin facts, rules and promises to a chat so the AI never forgets them.
- **📚 Auto-summarization:** Old messages are summarized in the background to keep long stories inside the model's context window.
- **🔄 Character.AI import / TXT export:** Drop in a `.txt` history exported from Character.AI, or download any chat as `{user}` / `{bot}` tagged text.

### Make it yours
- **🧩 10 layouts** — not recolours, different interfaces: Studio, Rail, Trio, Zen, Deck, Console, Ledger, Split, Canvas, Tiles.
- **🎨 6 palettes** (Graphite, Aurora, Vellum, Clay, Void, Sherbet) × any accent colour. The whole palette is rebuilt around the colour you pick, for light and dark mode.
- **💬 240 bubble designs** in 16 families — classics, gradients, neumorphism, retro terminals, animated "living" effects, emoji patterns, scenery, ears and paws… Give the AI and yourself different designs, recolour any of them, set how see-through they are, and let **Readable text** darken the words automatically when a design is too bright behind them.
- **🫧 Liquid glass:** Real refraction — the sidebar, header, bubbles and buttons bend the wallpaper behind them — with a frost slider. Switches itself off when your system asks for reduced transparency.
- **🖼️ Wallpapers:** An image or a video link (`.mp4`, `.webm`, `.mov` play muted and looping), or a file straight from your device (up to 120 MB, kept on that device). Dim, blur and show-through controls.
- **🖱️ Custom cursor:** Built-in cursors, a cursor page link (e.g. rw-designer.com), a direct `.png` / `.gif` / `.cur` link, or your own upload — with an adjustable click point and size.
- **👥 A look per character:** Every appearance setting can apply **everywhere**, to **one persona**, or to **one chat**. Open a character's chat and the bubbles, accent colour and wallpaper change with them.
- **☁️ Your look follows your account:** Appearance is stored in the database, so a second device picks it up when you sign in. Only a wallpaper picked from a device's own files stays on that device.
- **🗂️ Docked panels:** In the Rail, Trio and Split layouts (on screens 1024 px and wider), panels like Personas, API Endpoints and Memory open in the side column instead of a popup. **Current Chat** folds the column away and gives the conversation the full width.

### Private and secure
- **🔐 Two-factor sign-in:** Any authenticator app (Google Authenticator, Aegis, 1Password…) plus one-time recovery codes. See the lockout rules below — they are strict on purpose.
- **🧱 Nothing of yours before sign-in:** Every endpoint that holds data needs a signed-in session. Signed out, all anyone gets is the login form — and wrong passwords lock their IP out for a while.
- **🧼 Sanitized output:** Everything the AI writes is cleaned before it is shown, and every response carries a Content Security Policy and hardened security headers.

### On your phone
- **📲 Installable:** Add it to your home screen on Android or iPhone and it opens like an app, with its own icon. There is deliberately no service worker, so an installed copy never keeps an offline copy of your chats.
- **📱 Built for touch:** 44 px tap targets, dialogs that always fit the visible screen (address bar and all), and glass effects taken off the things that scroll, so long chats stay smooth.

---

## 🛠️ Installation Guide

There are three ways to install. **The fastest is the button below** — Cloudflare does everything. Method A is for doing it yourself from your own machine. Method B is for installing nothing locally and working entirely in the dashboard.

### Prerequisites
- A [Cloudflare](https://dash.cloudflare.com) account (Free tier is perfect).
- An API Key from an AI provider (e.g., [GroqCloud](https://console.groq.com/home)).
- For Method A: [Node.js](https://nodejs.org) (LTS) installed on your computer.

---

### ⚡ Fastest — one button (≈2 minutes)

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/redsusvn/rsroleplay)

Click it and sign in to Cloudflare. Cloudflare then:

1. copies the source into your own GitHub account,
2. creates a fresh **D1 database**,
3. creates the `ChatStreamer` **Durable Object** (what keeps long replies from being cut off),
4. deploys the Worker and hands you the URL.

There is no secret to fill in — the whole app needs only those two bindings. Open the URL and you land on the admin-account screen (see [First run](#first-time-setup--admin-account)).

To update later, replace `worker.js` in your copy of the repository and commit — Cloudflare redeploys on its own.

> The database tables are created by the app itself on first run, so there is no migration step to run by hand.

---

### Method A — Deploy it yourself with `wrangler` (≈10 minutes)

> **Why this matters:** a plain Worker on the Free plan gets only **10 ms of CPU per request**, which a long streamed reply exceeds — Cloudflare then kills the request mid-reply. The engine therefore runs each reply inside a **Durable Object**, which gets **30 s of CPU** and keeps running after you close the page. A Durable Object can only be created by a *migration*, which the dashboard cannot do — `wrangler` can.

> **💡 Shortcut — the setup helper.** Instead of Steps 3–5 below, you can run
> ```bash
> node setup/server.mjs
> ```
> and open **http://127.0.0.1:8788**. It walks you through creating an API token (it tells you exactly which permissions to tick: *Workers Scripts · Edit*, *D1 · Edit*, and optionally *Account Settings · Read*), picking your account, naming the Worker and creating the database, then writes a ready-to-use `wrangler.toml` for you. You still run `npx wrangler deploy` yourself (Step 6). It is one file with no dependencies, it only listens on your own machine, and the token never touches your disk. *(Its interface is in Vietnamese.)*

#### Step 1: Get the files
Download this repository (**Code → Download ZIP**) and unzip it. You need two files in the same folder: `worker.js` and `wrangler.toml`.

#### Step 2: Open a terminal in that folder
Windows: open the folder in Explorer, click the address bar, type `powershell`, press Enter.
macOS/Linux: open Terminal and `cd` into the folder.

#### Step 3: Log in to Cloudflare
```bash
npx wrangler login
```
The first run asks to install wrangler — answer `y`. A Cloudflare page opens in your browser: click **Allow**.

#### Step 4: Create the database
```bash
npx wrangler d1 create rsroleplay-db
```
The output contains a `database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"` line. Copy that UUID.

#### Step 5: Edit `wrangler.toml`
Open `wrangler.toml` in any text editor and set these three lines:
```toml
name = "myownchatplatform"          # the name your Worker (and its URL) will have
database_name = "rsroleplay-db"     # the name you used in Step 4
database_id = "PASTE-THE-UUID-FROM-STEP-4"
```
Leave the rest of the file as it is — it already declares the `DB` binding, the `STREAMER` Durable Object and its migration, the daily cleanup cron, and Smart Placement.

#### Step 6: Deploy
```bash
npx wrangler deploy
```
When it finishes you should see both bindings listed:
```
env.STREAMER (ChatStreamer)      Durable Object
env.DB (rsroleplay-db)           D1 Database
```
and your URL: `https://myownchatplatform.<your-subdomain>.workers.dev`.

Continue with **First-time setup** below.

---

### Method B — Dashboard only (no terminal, limited)

#### Step 1: Create a Cloudflare Worker
1. Log in to your Cloudflare Dashboard.
2. On the left sidebar, navigate to **Workers & Pages**.
3. Click **Create** -> **Create Worker**.
4. Name your worker (e.g., `myownchatplatform`) and click **Deploy**.

#### Step 2: Paste the Source Code
1. Once deployed, click **Edit Code** on your new Worker.
2. Delete all the default code in `worker.js`.
3. Copy the entire content of `worker.js` from this repository and paste it in.
4. Click **Deploy** in the top right corner.

#### Step 3: Finish it in Colab (database + Durable Object)

Your Worker now has the code but no database and no Durable Object. One script does both:

**[▶ Open the setup notebook in Google Colab](https://colab.research.google.com/drive/1TGZKllJQHez8J1ZaQEiOqyWNTTalenwQ?usp=sharing)** — or copy [`setup/colab-durable-object.py`](setup/colab-durable-object.py) into a blank notebook yourself.

Press run. The panel that appears has a button that opens Cloudflare's token page with the right permissions already ticked; paste the token back, pick your Worker, press **Cài đặt**. It will:

- create a D1 database (or bind one you already have) as `DB`, and
- install the `ChatStreamer` **Durable Object** — the one thing the dashboard cannot do, because it needs a *migration*.

It reads the code already running on your Worker and sends it back unchanged, so nothing you pasted in Step 2 is touched. The token stays in your own Colab session, goes only to `api.cloudflare.com`, and the script reminds you to delete it at the end.

Step-by-step in Vietnamese, for anyone who has never opened Colab: [`setup/HUONG-DAN-CAI-DURABLE-OBJECT.md`](setup/HUONG-DAN-CAI-DURABLE-OBJECT.md).

<details>
<summary>Prefer to click through the dashboard? (database only — no Durable Object)</summary>

1. In the Cloudflare sidebar, expand **Storage & databases** → **D1 SQL database** → **Create Database**. Name it `rsroleplay-db`.
2. Go to **Workers & Pages**, open your Worker, then **Settings** → **Bindings** → **Add Binding** → **D1 database**.
3. **Variable name:** exactly `DB` *(fully capitalized)*. **D1 database:** the one you just created. Save.

This gets the app running, but without the Durable Object — see the limitation below.
</details>

> **Without the Durable Object:** replies are generated inside the Worker's 10 ms CPU budget. Short and medium replies work; very long ones can be cut off by Cloudflare ("Worker exceeded CPU time limit" in the logs). Whatever arrived is still saved and you can press **Retry**. Run the Colab script above to fix it, or switch to Method A at any time: install Node.js, put your existing Worker name and database name/ID into `wrangler.toml` (the ID is on the D1 database page), then run `npx wrangler login` and `npx wrangler deploy`. Your chats are kept — it is the same database.

---

### First-time setup & Admin account
1. Open your Worker's `.workers.dev` URL in your browser.
2. You will be greeted by the First Time Setup screen.
3. Enter your desired Admin Username and Password.
   > *Note: You can only create ONE account for this private instance. Keep your credentials safe!*

### Connect your AI (API Endpoints)
1. Log in to your RSROLEPLAY instance.
2. Click **API Endpoints** in the left sidebar (or the **+** next to its close button).
3. Click **+ Add Endpoint**.
4. Select your provider (e.g., `Groq`), paste your API Key, then enter the Model ID — or press **Browse** to pick it from the provider's list (e.g., `llama-3.3-70b-versatile`).
5. Check the **Set as Primary** box and click **Save Key**. Press **Test** on the endpoint to make sure it answers.

### AI model names
- Chat model name: `google/gemma-4-26b-a4b-it`
- Summarize model name: `llama-3.3-70b-versatile`

### Recommended models
- OpenRouter: `nvidia/nemotron-3-super-120b-a12b:free`
- Gemini: `gemma-4-26b-a4b-it` and `gemma-4-31b-it`, both work well.

🎉 **You're done!** You can now go to "Current Chat" and start talking to your AI.

---

## 🔐 Two-factor sign-in

Turn it on in **Account Settings → Two-factor authentication**: scan the QR code with an authenticator app, confirm a code, and **save the recovery codes it shows you** — each one works once, and they are your only way in if you lose the phone.

The lockout is deliberately strict:

| Wrong codes | What happens |
|---|---|
| 3 | wait **10 minutes** |
| 1 more | wait **30 minutes** |
| 1 more | wait **1 hour** |
| 1 more | **the account is locked for good** — its name and password are replaced with random characters |

The login page never says which of these you are in — a wrong code only ever answers *"Please try again."* So don't guess: use a recovery code instead.

If it ever happens to you, your chats and keys are untouched. Clear the locked account from the command line and set up again — and do it in one go, because the site offers first-time setup to whoever opens it first:
```bash
npx wrangler d1 execute rsroleplay-db --remote --command "DELETE FROM users; DELETE FROM user_sessions"
```

---

## 🎨 Making it yours

Everything lives under **Appearance** in the sidebar:

- **Theme** — pick one of the 10 layouts.
- **Style** — extra options for the layout you picked.
- **Colour** — the palette and any accent colour; everything is rebuilt around it. (Dark or light: **Toggle Theme** in the sidebar.)
- **Bubble** — browse the 240 designs, for the AI's side, yours, or both.
- **Bubble setup** — recolour the chosen design, set its opacity, change the emoji of an emoji-pattern design, and toggle *Readable text*, *Outline behind text* and the design's own font.
- **More** — liquid glass, wallpaper, cursor.

**Applies to** at the top of the panel decides where a change lands: **Everywhere**, **this persona** or **this chat**. A persona-level look is how each character gets their own bubbles, colour and wallpaper — switch chats and the whole interface changes with them.

---

## 🎞️ Demo content

Want to see it full of life before you have written a single story? `demo/seed.sql` adds eight original characters with portraits, their own bubble designs and wallpapers, and a finished conversation each — with swipe variants, thought-process blocks, sketchboard pins and memory summaries.

```bash
npx wrangler d1 execute rsroleplay-db --remote --file demo/seed.sql
```

Use `--local` instead of `--remote` to try it on `wrangler dev` first. To take it all out again — and only it — run the same command with `demo/unseed.sql`. Your own personas, chats and keys are never touched: every demo row has an id starting with `demo-`. The one thing it adds to your settings is a look for each demo character, and `unseed.sql` takes those out too.

*The portraits and wallpapers are from [Pixabay](https://pixabay.com) (Pixabay Content License). The portraits are embedded in the database; the wallpapers load from Pixabay's servers.*

---

## ⬆️ Updating an existing installation

Your chats, personas, keys and appearance live in D1 and are kept across updates. The database schema upgrades itself on the first request after an update.

- **Installed with Method A:** download the new `worker.js` (and `wrangler.toml` if it changed) into your folder, keep your three edited lines, run `npx wrangler deploy`.
- **Installed with Method B:** open the Worker → **Edit Code**, replace everything with the new `worker.js`, click **Deploy**. Bindings are kept. To also get the Durable Object, follow the switch-over note under Method B.

After updating, just reload the app — the new version is picked up automatically.

---

## 💡 Pro Tips

### Importing from Character.AI
1. Use a C.AI history exporter extension to get a `.txt` file of your chat.
2. In RSROLEPLAY Engine, click **Data Sync**.
3. Drag and drop your `.txt` file into the "Import Session" box.
4. **Tip:** Use Google Gemini to summarize your C.AI history into a structured "Persona" and "System Prompt" so your bot acts exactly like it used to!

### Chat Summarization Prompt

```
### ROLE: Professional Narrative Analyst and Roleplay Architect
### TASK: Analyze the provided chat history to create a comprehensive "Story Bible." 
Your goal is to extract every essential data point, nuance, and plot thread to ensure the conversation can be resumed with 100% consistency. You must condense the history into a structured, high-density briefing for a future AI model.
---
### OUTPUT FORMAT
Follow this structure EXACTLY. Use the headers provided.
{PROMPT AND INFORMATION}
[BOT CHARACTER INFO]
* Name: 
* Personality & Core Traits: (A deep dive into their psyche, temperament, and hidden layers)
* Backstory/Lore: (History and secrets revealed during the chat)
* Physical Description: (Appearance, unique features, current attire)
[USER INFO]
* Name/Role: 
* Character Traits: 
* Current Motivation: (What is the user character currently trying to achieve?)
[CONVERSATION & NARRATIVE STYLE]
* Chatting Style: (e.g., Casual, formal, average length of responses, use of OOC)
* Bot Talking Style: (Vocabulary choices, accents, stutters, specific sentence structures, or catchphrases)
* Narrative Style: (Detailed description of the "Narrator" voice—e.g., poetic, gritty, third-person limited, first-person, focusing on internal monologue vs. external action)
{CHAT HISTORY}
[THE CHRONOLOGICAL TIMELINE]
Provide a detailed, bulleted summary of the story from the first message to the current moment:
* Major Plot Points: (Key events that drove the story forward)
* Emotional Milestones: (Shifts in the relationship dynamics, e.g., trust built, betrayal, romance)
* Key Revelations: (Facts or lore uncovered during the roleplay)
* Current Location/Context: (Exactly where the characters are, the time of day, and the immediate situation)
{SPECIFIC REQUIREMENT FOR CHAT}
[CONTINUATION DIRECTIVES]
* Storytelling Quality: (Analyze what made the history successful and instruct the AI on how to maintain it—e.g., "prioritize sensory details," "maintain slow-burn tension," or "focus on psychological realism")
* The "Vibe" to Maintain: (The specific atmosphere—e.g., Noir, Whimsical, Gothic Horror, High-Fantasy)
* Specific Constraints: (Operational rules based on the history—e.g., "Never speak for the user," "Always put internal thoughts in italics," "Keep responses under 3 paragraphs")
* Immediate Next Goal: (The specific focus for the very next response to maintain the current momentum)
---
### INPUT DATA: CHAT HISTORY BEGINS BELOW
[PASTE YOUR CHAT HISTORY HERE]
```

---

### Memory Optimization
If your bot starts acting forgetful, go to **Memory Rules**. Ensure the `Messages to Summarize` threshold is properly set based on your AI model's context window.

### Give each character a face
A persona's **Avatar** field takes an image link, an inline image (`data:image/png`, `jpeg`, `webp` or `gif`), an emoji, or two letters. Inline images travel with the character and never break because a host went down.

---

## ❓ Troubleshooting

- **"D1 database binding 'DB' not found"** — the `DB` binding is missing. Method B: redo Step 4. Method A: check `database_name` / `database_id` in `wrangler.toml` and deploy again (wrangler replaces the bindings with what is in that file).
- **Long replies stop partway / "Worker exceeded CPU time limit" in Observability** — you are running without the Durable Object. Switch to Method A.
- **A reply says "No reply was generated — your message was saved"** — the AI provider failed. Your message is kept; press **Retry**. Check the endpoint in **API Endpoints** with its **Test** button.
- **Replies appear all at once instead of streaming** — an ad blocker or privacy extension is holding back the live stream until it finishes. Add your Worker's address to its allow-list.
- **My look didn't follow me to another device** — it is pulled when you sign in, so reload once on the other device. A wallpaper picked from a device's own files is the one thing that stays on that device.
- **An avatar shows two letters instead of the picture** — the link must start with `http` or be an inline `png` / `jpeg` / `webp` / `gif` image. SVG is not accepted.
- **Locked out by two-factor** — wait out the timer in the table above, or use a recovery code. After the final wrong code the account is locked for good, so don't guess — the fix is in the Two-factor section above.
- **Where is the Durable Object?** — Dashboard → **Workers & Pages → Durable Objects** should list `ChatStreamer` after a Method A deploy, and the Worker's **Bindings** tab should show `STREAMER`.
