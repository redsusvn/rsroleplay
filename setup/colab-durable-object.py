# RSROLEPLAY — hoàn tất cài đặt trên Cloudflare
#
# Cách dùng: mở https://colab.research.google.com → New notebook → dán TOÀN BỘ
# file này vào ô trống → bấm nút ▶ bên trái.
#
# Sẽ hiện ra một bảng: bấm link lấy token, dán vào, chọn Worker từ danh sách
# rồi bấm nút cài. Không phải gõ gì ngoài việc dán token.
#
# Nó làm hai việc mà trang quản trị Cloudflare làm không tiện hoặc không được:
#
#   1. Nối database D1 vào Worker (tạo mới nếu bạn chưa có) — làm bằng tay
#      được, nhưng phải bấm qua vài trang và gõ đúng chữ DB in hoa.
#   2. Cài Durable Object ChatStreamer — cái này thì dashboard chịu, vì nó cần
#      một thứ gọi là migration mà chỉ công cụ dòng lệnh hoặc API mới chạy được.
#
# Code trên Worker của bạn không bị sửa: script tải đúng đoạn đang chạy về rồi
# gửi lại y nguyên, chỉ kèm thêm phần cài đặt.

import json
import re
import time
from urllib.parse import urlencode

import requests

CF = "https://api.cloudflare.com/client/v4"
CLASS_NAME = "ChatStreamer"
BINDING_NAME = "STREAMER"
DB_BINDING = "DB"
TEN_DB_MAC_DINH = "rsroleplay-db"

# Link mở thẳng trang tạo token, kèm sẵn 3 quyền cần thiết. Tham số này không
# nằm trong tài liệu của Cloudflare, nên nếu có ngày họ đổi thì trang vẫn mở ra
# bình thường, chỉ là phải tự tick theo bảng hiện bên dưới.
TOKEN_URL = "https://dash.cloudflare.com/profile/api-tokens?" + urlencode({
    "permissionGroupKeys": json.dumps([
        {"key": "workers_scripts", "type": "edit"},
        {"key": "account_settings", "type": "read"},
        {"key": "d1", "type": "edit"},
    ], separators=(",", ":")),
    "name": "rsroleplay-setup",
    "accountId": "*",
    "zoneId": "all",
})


class Loi(Exception):
    """Lỗi có thể đọc được, để hiện thẳng cho người dùng."""


# ── phần lõi: không dính gì tới giao diện ───────────────────────────────

def api(s, method, path, **kw):
    r = s.request(method, CF + path, timeout=120, **kw)
    try:
        return r.json()
    except Exception:
        return {"success": False, "errors": [{"message": r.text[:300]}]}


def loi_cua(res):
    return "; ".join((e.get("message") or "") for e in (res.get("errors") or [])) or "không rõ lý do"


def mo_phien(token):
    """Kiểm tra token, trả về (phiên làm việc, danh sách tài khoản)."""
    s = requests.Session()
    s.headers.update({"Authorization": "Bearer " + token.strip()})
    if not api(s, "GET", "/user/tokens/verify").get("success"):
        raise Loi("Token này không dùng được. Thường là do chép thiếu một đoạn, "
                  "hoặc token đã bị xoá. Tạo token mới rồi thử lại.")
    accs = api(s, "GET", "/accounts").get("result") or []
    if not accs:
        raise Loi("Token đúng, nhưng không thấy tài khoản nào. Lúc tạo token "
                  "bạn thiếu dòng: Account | Account Settings | Read.")
    return s, accs


def danh_sach_worker(s, acct):
    res = api(s, "GET", "/accounts/%s/workers/scripts" % acct)
    if not res.get("success"):
        raise Loi("Không đọc được danh sách Worker: " + loi_cua(res))
    names = [w["id"] for w in (res.get("result") or [])]
    if not names:
        raise Loi("Tài khoản này chưa có Worker nào. Bạn cần dán worker.js vào "
                  "Cloudflare trước đã — xem Cách B trong README.")
    return names


def danh_sach_d1(s, acct):
    """[(tên, uuid)] các database D1 đang có."""
    res = api(s, "GET", "/accounts/%s/d1/database" % acct)
    if not res.get("success"):
        raise Loi("Không đọc được danh sách database: " + loi_cua(res) +
                  "\nLúc tạo token có thể bạn thiếu dòng: Account | D1 | Edit.")
    return [(d.get("name") or d["uuid"], d["uuid"]) for d in (res.get("result") or [])]


def tao_d1(s, acct, ten):
    """Tạo database mới; nếu trùng tên thì dùng lại cái đã có."""
    res = api(s, "POST", "/accounts/%s/d1/database" % acct, json={"name": ten})
    if res.get("success"):
        return (res.get("result") or {}).get("uuid")
    for co_ten, uuid in danh_sach_d1(s, acct):
        if co_ten == ten:
            return uuid
    raise Loi("Không tạo được database: " + loi_cua(res))


def cai_dat_hien_tai(s, acct, name):
    res = api(s, "GET", "/accounts/%s/workers/scripts/%s/settings" % (acct, name))
    if not res.get("success"):
        raise Loi("Không đọc được cài đặt của Worker: " + loi_cua(res))
    return res.get("result") or {}


def co_binding(binds, ten, kieu=None):
    return any(b.get("name") == ten and (kieu is None or b.get("type") == kieu) for b in binds)


def tai_code(s, acct, name):
    """Tải đúng đoạn code đang chạy. Trả về (các file, tên file chính)."""
    r = s.get("%s/accounts/%s/workers/scripts/%s" % (CF, acct, name),
              headers={"Accept": "*/*"}, timeout=120)
    if r.status_code != 200:
        raise Loi("Không tải được code của Worker (HTTP %d)." % r.status_code)

    ctype = r.headers.get("Content-Type", "")
    if "multipart" not in ctype:
        return {"worker.js": r.content}, "worker.js"

    m = re.search(r'boundary="?([^";]+)"?', ctype)
    if not m:
        raise Loi("Cloudflare trả về định dạng lạ, không đọc được code.")
    modules = {}
    for part in r.content.split(("--" + m.group(1)).encode()):
        if b"\r\n\r\n" not in part:
            continue
        head, body = part.split(b"\r\n\r\n", 1)
        ten = re.search(r'name="([^"]+)"', head.decode("utf-8", "replace"))
        if ten:
            modules[ten.group(1)] = body.rstrip(b"\r\n")
    if not modules:
        raise Loi("Tải được code nhưng không đọc ra file nào bên trong.")
    return modules, ("worker.js" if "worker.js" in modules else sorted(modules)[0])


def hoan_tat_cai_dat(s, acct, name, d1_id=None, log=print):
    """Nối database (nếu cần) và cài Durable Object (nếu cần)."""
    cur = cai_dat_hien_tai(s, acct, name)
    binds = cur.get("bindings") or []
    tag = cur.get("migration_tag") or ""

    can_do = not co_binding(binds, BINDING_NAME, "durable_object_namespace")
    can_db = (not co_binding(binds, DB_BINDING)) and bool(d1_id)
    if not can_do and not can_db:
        return {"da_du": True, "bindings": binds}

    modules, main = tai_code(s, acct, name)
    if CLASS_NAME.encode() not in modules[main]:
        raise Loi("Code trên Worker này không có phần %s, nên chưa cài được.\n"
                  "Nghĩa là Worker đang chạy bản cũ: vào Cloudflare → Worker của bạn → "
                  "Edit Code, dán worker.js mới nhất vào, bấm Deploy, rồi làm lại." % CLASS_NAME)
    log("✓ Đã tải code đang chạy (%d file)" % len(modules))

    giu = []
    for b in binds:
        # secret chỉ trả về tên, không trả về giá trị; gửi lại kiểu "inherit"
        # để Cloudflare giữ nguyên thay vì ghi đè thành rỗng
        giu.append({"type": "inherit", "name": b.get("name")}
                   if b.get("type") in ("secret_text", "inherit") else b)
    if can_db:
        giu.append({"type": "d1", "name": DB_BINDING, "id": d1_id})
        log("✓ Sẽ nối database vào binding tên %s" % DB_BINDING)
    if can_do:
        giu.append({"type": "durable_object_namespace", "name": BINDING_NAME, "class_name": CLASS_NAME})
        log("✓ Sẽ cài Durable Object %s" % CLASS_NAME)

    meta = {
        "main_module": main,
        "bindings": giu,
        "compatibility_date": cur.get("compatibility_date") or "2026-09-01",
    }
    if can_do:
        meta["migrations"] = {"new_tag": (tag + "-do") if tag else "v1",
                              "new_sqlite_classes": [CLASS_NAME]}
        if tag:
            meta["migrations"]["old_tag"] = tag
    for k in ("placement", "observability", "compatibility_flags", "usage_model"):
        if cur.get(k):
            meta[k] = cur[k]

    def gui(metadata):
        files = {"metadata": (None, json.dumps(metadata), "application/json")}
        for fn, body in modules.items():
            files[fn] = (fn, body, "application/javascript+module")
        return api(s, "PUT", "/accounts/%s/workers/scripts/%s" % (acct, name), files=files)

    log("… đang gửi lên Cloudflare, chờ vài giây")
    res = gui(meta)
    if not res.get("success"):
        msg = loi_cua(res).lower()
        if "inherit" in msg:
            meta["bindings"] = [b for b in giu if b.get("type") != "inherit"]
            res = gui(meta)
        elif "migration" in msg or "tag" in msg:
            meta.pop("migrations", None)
            res = gui(meta)
    if not res.get("success"):
        raise Loi("Cloudflare không nhận bản cập nhật: " + loi_cua(res) +
                  "\nCode trên Worker của bạn KHÔNG bị thay đổi.")

    time.sleep(2)
    binds2 = (cai_dat_hien_tai(s, acct, name).get("bindings")) or []
    sub = (api(s, "GET", "/accounts/%s/workers/subdomain" % acct).get("result") or {}).get("subdomain")
    return {
        "da_du": False,
        "co_do": co_binding(binds2, BINDING_NAME, "durable_object_namespace"),
        "co_db": co_binding(binds2, DB_BINDING),
        "bindings": binds2,
        "url": ("https://%s.%s.workers.dev" % (name, sub)) if sub else None,
    }


def mo_ta_binding(binds):
    return ", ".join("%s (%s)" % (b.get("name"), b.get("type")) for b in binds) or "không có gì"


# ── giao diện bấm chọn (Colab) ──────────────────────────────────────────

def giao_dien():
    import ipywidgets as w
    from IPython.display import display, HTML

    display(HTML("""
<style>.rs-box{border:1px solid #d0d7de;border-radius:10px;padding:14px 16px;margin:8px 0}
.rs-h{font-weight:600;font-size:15px;margin-bottom:6px}</style>
<div class="rs-box">
  <div class="rs-h">Hoàn tất cài đặt RSROLEPLAY</div>
  Sau khi bạn dán <code>worker.js</code> vào Cloudflare, còn hai việc trang quản trị làm không tiện
  hoặc không làm được. Script này lo cả hai:<br><br>
  <b>1. Nối database.</b> Tạo database D1 nếu bạn chưa có, rồi nối vào Worker đúng tên <code>DB</code>.<br>
  <b>2. Cài Durable Object.</b> Đây mới là phần dashboard chịu — nó cần một <i>migration</i>, thứ chỉ
  công cụ dòng lệnh hoặc API chạy được. Thiếu nó thì câu trả lời dài của AI hay bị cắt giữa chừng,
  vì Worker thường chỉ được 10 mili giây CPU mỗi lượt còn Durable Object được 30 giây.<br><br>
  Code trên Worker của bạn <b>không bị sửa</b>: script tải đúng đoạn đang chạy về rồi gửi lại y nguyên.
</div>"""))

    display(HTML("""
<div class="rs-box">
  <div class="rs-h">Bước 1 — Lấy token</div>
  <a href="%s" target="_blank" rel="noopener"
     style="display:inline-block;background:#f38020;color:#fff;text-decoration:none;
            padding:9px 16px;border-radius:8px;font-weight:600">Mở trang tạo token ↗</a>
  <div style="margin-top:10px">
    Trang mở ra ở tab mới, thường đã chọn sẵn đúng quyền — bạn chỉ cần kéo xuống bấm
    <b>Continue to summary</b> rồi <b>Create Token</b>, và bấm <b>Copy</b>.
    <br>Nếu trang hiện ra trống, bấm <b>Create Token</b> → <b>Create Custom Token</b> và tự tick 3 dòng:
    <table style="margin-top:6px;border-collapse:collapse">
      <tr><td style="padding:2px 10px 2px 0">Account</td><td style="padding:2px 10px 2px 0">Workers Scripts</td><td><b>Edit</b></td></tr>
      <tr><td style="padding:2px 10px 2px 0">Account</td><td style="padding:2px 10px 2px 0">Account Settings</td><td><b>Read</b></td></tr>
      <tr><td style="padding:2px 10px 2px 0">Account</td><td style="padding:2px 10px 2px 0">D1</td><td><b>Edit</b></td></tr>
    </table>
    <div style="margin-top:6px;color:#57606a">Token chỉ hiện một lần. Chép xong quay lại đây.</div>
  </div>
</div>""" % TOKEN_URL))

    o_token = w.Password(placeholder="Dán token vào đây", layout=w.Layout(width="440px"))
    nut_kiem = w.Button(description="Kiểm tra token", button_style="primary", icon="check")
    nhat_ky = w.Output()

    rong = w.Layout(width="460px")
    nhan = {"description_width": "110px"}
    o_acct = w.Dropdown(description="Tài khoản:", layout=rong, style=nhan)
    o_worker = w.Dropdown(description="Worker:", layout=rong, style=nhan)
    o_d1 = w.Dropdown(description="Database:", layout=rong, style=nhan)
    ghi_chu_d1 = w.HTML("")
    khung_d1 = w.VBox([ghi_chu_d1, o_d1])
    nut_cai = w.Button(description="Cài đặt", button_style="success", icon="rocket",
                       layout=w.Layout(width="220px"))
    khung_chon = w.VBox([o_acct, o_worker, khung_d1, nut_cai])
    khung_chon.layout.display = "none"
    khung_d1.layout.display = "none"

    display(HTML('<div class="rs-h" style="margin-top:12px">Bước 2 — Dán token rồi bấm kiểm tra</div>'))
    display(w.HBox([o_token, nut_kiem]), khung_chon, nhat_ky)

    tt = {}

    def ghi(dong):
        with nhat_ky:
            print(dong)

    def bao_loi(e):
        with nhat_ky:
            print("\n❌ " + str(e))

    def khi_kiem_tra(_):
        nhat_ky.clear_output()
        khung_chon.layout.display = "none"
        nut_kiem.disabled, nut_kiem.description = True, "Đang kiểm tra…"
        try:
            s, accs = mo_phien(o_token.value)
            tt["s"] = s
            ghi("✓ Token dùng được")
            o_acct.options = [(a.get("name") or a["id"], a["id"]) for a in accs]
            # ipywidgets 8 does not select anything when options are
            # assigned to a dropdown that started empty
            o_acct.index = 0 if o_acct.options else None
            o_acct.layout.display = "none" if len(accs) == 1 else "flex"
            doi_tai_khoan()
            khung_chon.layout.display = "flex"
        except Loi as e:
            bao_loi(e)
        except Exception as e:
            bao_loi("Có trục trặc ngoài dự tính: %s" % e)
        finally:
            nut_kiem.disabled, nut_kiem.description = False, "Kiểm tra token"

    def doi_tai_khoan(*_):
        if "s" not in tt or not o_acct.value:
            return
        try:
            names = danh_sach_worker(tt["s"], o_acct.value)
            o_worker.options = names
            o_worker.index = 0 if names else None
            o_worker.layout.display = "none" if len(names) == 1 else "flex"
            ghi("✓ Tìm thấy %d Worker%s" % (len(names), ": " + names[0] if len(names) == 1 else ""))
            doi_worker()
        except Loi as e:
            bao_loi(e)

    def doi_worker(*_):
        """Chỉ hỏi database khi Worker chưa nối cái nào."""
        if "s" not in tt or not o_worker.value:
            return
        try:
            binds = cai_dat_hien_tai(tt["s"], o_acct.value, o_worker.value).get("bindings") or []
            if co_binding(binds, DB_BINDING):
                khung_d1.layout.display = "none"
                ghi("✓ Worker đã nối sẵn database")
                return
            dbs = danh_sach_d1(tt["s"], o_acct.value)
            o_d1.options = [("➕ Tạo database mới tên %s" % TEN_DB_MAC_DINH, "__moi__")] + \
                           [("%s" % ten, uuid) for ten, uuid in dbs]
            o_d1.index = 0
            ghi_chu_d1.value = ('<div style="color:#9a6700">Worker này chưa nối database. '
                                'Chọn một cái có sẵn, hoặc để script tạo mới.</div>')
            khung_d1.layout.display = "flex"
        except Loi as e:
            bao_loi(e)

    def khi_cai(_):
        nut_cai.disabled, nut_cai.description = True, "Đang cài…"
        try:
            d1_id = None
            if khung_d1.layout.display != "none":
                if o_d1.value == "__moi__":
                    ghi("… đang tạo database %s" % TEN_DB_MAC_DINH)
                    d1_id = tao_d1(tt["s"], o_acct.value, TEN_DB_MAC_DINH)
                    ghi("✓ Đã có database")
                else:
                    d1_id = o_d1.value
            kq = hoan_tat_cai_dat(tt["s"], o_acct.value, o_worker.value, d1_id=d1_id, log=ghi)
            if kq.get("da_du"):
                with nhat_ky:
                    display(HTML('<div style="color:#1a7f37;font-weight:600;margin-top:8px">'
                                 '✅ Worker này đã đủ cả database lẫn Durable Object. '
                                 'Không cần làm gì thêm.</div>'))
                return
            xong = kq["co_do"] and (kq["co_db"] or khung_d1.layout.display == "none")
            dia_chi = ('<br>Địa chỉ web: <a href="%s" target="_blank">%s</a>'
                       % (kq["url"], kq["url"])) if kq.get("url") else ""
            with nhat_ky:
                display(HTML(
                    '<div style="border-left:4px solid %s;padding:8px 12px;margin-top:8px;background:#f6f8fa">'
                    '<b>%s</b><br>Worker đang có: %s%s<br><br>'
                    'Việc cuối: quay lại <a href="https://dash.cloudflare.com/profile/api-tokens" '
                    'target="_blank">trang token</a> xoá token vừa dùng đi.</div>'
                    % ("#1a7f37" if xong else "#9a6700",
                       "✅ XONG! Mọi thứ đã sẵn sàng." if xong
                       else "⚠ Đã gửi xong nhưng chưa thấy đủ — chờ một phút rồi bấm lại.",
                       mo_ta_binding(kq["bindings"]), dia_chi)))
        except Loi as e:
            bao_loi(e)
        except Exception as e:
            bao_loi("Có trục trặc ngoài dự tính: %s" % e)
        finally:
            nut_cai.disabled, nut_cai.description = False, "Cài đặt"

    nut_kiem.on_click(khi_kiem_tra)
    nut_cai.on_click(khi_cai)
    o_acct.observe(doi_tai_khoan, names="value")
    o_worker.observe(doi_worker, names="value")


# ── bản chữ, phòng khi giao diện không chạy được ────────────────────────

def ban_chu():
    import getpass
    print("Mở link này để tạo token (3 quyền: Workers Scripts=Edit, "
          "Account Settings=Read, D1=Edit):\n" + TOKEN_URL + "\n")
    s, accs = mo_phien(getpass.getpass("Dán token rồi Enter: "))
    print("✓ Token dùng được")

    def chon(cai_gi, muc):
        if len(muc) == 1:
            return muc[0][1]
        for i, (ten, _) in enumerate(muc, 1):
            print("   %d. %s" % (i, ten))
        return muc[int(input("Chọn %s (gõ số): " % cai_gi)) - 1][1]

    acct = chon("tài khoản", [(a.get("name") or a["id"], a["id"]) for a in accs])
    name = chon("Worker", [(n, n) for n in danh_sach_worker(s, acct)])

    d1_id = None
    if not co_binding(cai_dat_hien_tai(s, acct, name).get("bindings") or [], DB_BINDING):
        print("\nWorker này chưa nối database.")
        muc = [("Tạo database mới tên %s" % TEN_DB_MAC_DINH, "__moi__")] + \
              [(t, u) for t, u in danh_sach_d1(s, acct)]
        chon_d1 = chon("database", muc)
        d1_id = tao_d1(s, acct, TEN_DB_MAC_DINH) if chon_d1 == "__moi__" else chon_d1

    kq = hoan_tat_cai_dat(s, acct, name, d1_id=d1_id)
    if kq.get("da_du"):
        print("\n✅ Worker này đã đủ cả database lẫn Durable Object.")
        return
    print("\n✅ XONG!" if kq["co_do"] else "\n⚠ Đã gửi xong nhưng chưa thấy đủ, chờ một phút rồi chạy lại.")
    print("   Worker đang có: " + mo_ta_binding(kq["bindings"]))
    if kq.get("url"):
        print("   Địa chỉ: " + kq["url"])
    print("\nNhớ vào dash.cloudflare.com/profile/api-tokens xoá token vừa dùng.")


def main():
    try:
        import ipywidgets  # noqa: F401
        giao_dien()
    except ImportError:
        ban_chu()
    except Loi as e:
        print("❌ " + str(e))


if __name__ == "__main__":
    main()
