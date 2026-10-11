/*
 * Trang tra cứu bài làm (U49, PHIÊN BẢN 2). Chạy hoàn toàn trên trình duyệt, không có máy chủ.
 * Quy tắc mã hóa phải KHỚP src/services/lookup_service.py và src/core/lookup_code.py (docs/BAO_MAT_TRA_CUU.md):
 *   mã chuẩn: chữ hoa, chỉ giữ 0-9 A-Z, O→0, I/L→1; 16 ký tự Crockford, ký tự cuối = ALPHABET[sha256(tiền tố + 15 ký tự)[31] & 31]
 *   dk = PBKDF2-SHA256(mã, "GRADE-tra-cuu-v2|" + muối, số vòng) → 32 byte (MỘT khối)
 *   khóa AES = HMAC(dk, "GRADE-v2 aes" || 0x01); khóa tên = HMAC(dk, "GRADE-v2 ten-file" || 0x01)   (HKDF-Expand)
 *   file k/<kỳ thi>/<id = hex(HMAC(khóa tên, kỳ thi))[0:32]>.bin = nonce 12 byte + AES-GCM(aad = kỳ thi + "|" + id)
 *   dữ liệu = 4 byte độ dài JSON + JSON + ảnh JPEG
 * Mã tra cứu nằm sau dấu # (trình duyệt KHÔNG gửi lên máy chủ); đọc xong thì xóa khỏi thanh địa chỉ.
 */
"use strict";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CHECK_PREFIX = "GRADE-ma-tra-cuu|";
const KDF_PREFIX = "GRADE-tra-cuu-v2|";
const SITE_VERSION = 2;
const CODE_LEN = 16;
const enc = new TextEncoder();
const $ = (id) => document.getElementById(id);
let imageUrls = [];

function normalize(text) {
  return text.toUpperCase().replace(/[^0-9A-Z]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
}

function pretty(code) {
  return (code.match(/.{1,4}/g) || []).join("-");
}

async function isValid(code) {
  if (code.length !== CODE_LEN || [...code].some((c) => !ALPHABET.includes(c))) return false;
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(CHECK_PREFIX + code.slice(0, CODE_LEN - 1))));
  return ALPHABET[d[31] & 31] === code[CODE_LEN - 1];
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

async function expand(dk, label) {                 // HKDF-Expand, một khối: HMAC(dk, label || 0x01)
  const k = await crypto.subtle.importKey("raw", dk, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, concat(enc.encode(label), new Uint8Array([1]))));
}

async function deriveKeys(code, salt, iterations) {
  const base = await crypto.subtle.importKey("raw", enc.encode(code), "PBKDF2", false, ["deriveBits"]);
  const dk = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: concat(enc.encode(KDF_PREFIX), salt), iterations }, base, 256));
  const aes = await crypto.subtle.importKey("raw", await expand(dk, "GRADE-v2 aes"), "AES-GCM", false, ["decrypt"]);
  const name = await crypto.subtle.importKey("raw", await expand(dk, "GRADE-v2 ten-file"),
                                             { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return { aes, name };
}

async function fileId(nameKey, slug) {
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", nameKey, enc.encode(slug)));
  return [...mac.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function fetchJson(path) {
  const r = await fetch(path, { cache: "no-cache" });
  if (!r.ok) throw new Error(path);
  return r.json();
}

async function loadExam(keys, exam) {
  const id = await fileId(keys.name, exam.slug);
  const r = await fetch(`k/${exam.slug}/${id}.bin`, { cache: "no-cache" });
  if (!r.ok) return null;                      // em không dự kỳ thi này
  const blob = new Uint8Array(await r.arrayBuffer());
  const plain = new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: blob.slice(0, 12), additionalData: enc.encode(`${exam.slug}|${id}`) }, keys.aes, blob.slice(12)));
  const n = new DataView(plain.buffer).getUint32(0);
  const data = JSON.parse(new TextDecoder().decode(plain.slice(4, 4 + n)));
  const image = plain.length > 4 + n ? new Blob([plain.slice(4 + n)], { type: "image/jpeg" }) : null;
  return { data, image };
}

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v; else e.setAttribute(k, v);
  }
  for (const c of children) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
}

function showAnswer(part, value) {
  const v = String(value || "");
  if (part === 2) {
    if (!v || /^_+$/.test(v)) return "—";
    return [...v].map((c) => (c === "D" ? "Đ" : c === "S" ? "S" : "·")).join(" ");
  }
  const t = v.replace(/_/g, "");
  if (!t) return "—";
  return part === 1 && t.length > 1 ? [...t].join(",") : t.replace(".", ",");
}

const RESULT_TEXT = { ok: "Đúng", part: "Đúng một phần", no: "Sai" };

function renderExam(found, open) {
  const d = found.data;
  const score = d.score ? el("div", { class: "score" }, d.score, el("small", {}, ` / ${d.max}`))
                        : el("div", { class: "score" }, el("small", {}, "Không có điểm"));
  const head = el("summary", {}, el("div", {}, el("div", { class: "title" }, d.exam),
                                     el("div", { class: "date" }, `Công bố: ${d.published}`)), score);
  const body = el("div", { class: "body" });
  body.append(el("div", { class: "meta" },
    el("div", {}, "Số báo danh: ", el("b", {}, d.sbd)),
    el("div", {}, "Mã đề: ", el("b", {}, d.exam_code || "—")),
    el("div", {}, "Phòng thi: ", el("b", {}, d.room || "—")),
    el("div", {}, "Lớp: ", el("b", {}, d.class || "—"))));
  if (d.violation) body.append(el("div", { class: "note" },
    `Điểm đã trừ theo Quy chế thi do vi phạm: ${d.violation}. Điểm từng câu bên dưới là điểm chấm bài.`));
  for (const p of d.parts || []) {
    body.append(el("h3", {}, p.label));
    const tb = el("tbody");
    for (const r of p.rows) {
      tb.append(el("tr", { class: r.result },
        el("td", {}, r.q), el("td", { class: "mono" }, showAnswer(p.part, r.chosen)),
        el("td", { class: "mono" }, r.key_text || showAnswer(p.part, r.key)),
        el("td", { class: "res" }, `${r.points} / ${r.max}`)));
    }
    body.append(el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "Câu"), el("th", {}, "Em chọn"),
                                                   el("th", {}, "Đáp án"), el("th", {}, "Điểm"))), tb));
  }
  if ((d.parts || []).length) {
    body.append(el("div", { class: "legend" }, "Xanh: đúng · Vàng: đúng một phần (Phần II) · Đỏ: sai. " +
                                               "Phần II: Đ = Đúng, S = Sai, · = bỏ trống; — = bỏ trống."));
  }
  if (found.image) {
    const url = URL.createObjectURL(found.image);
    imageUrls.push(url);
    const img = el("img", { src: url, alt: "Ảnh phiếu trả lời đã quét" });
    img.addEventListener("click", () => openViewer(url));
    body.append(el("div", { class: "sheet" }, el("h3", {}, "Ảnh phiếu trả lời đã quét (chạm để phóng to)"), img));
  } else if (d.image_error) {
    body.append(el("p", { class: "legend" }, "Không có ảnh phiếu. Hỏi giáo viên bộ môn nếu cần xem."));
  }
  if (d.seal) body.append(el("div", { class: "seal" }, `Niêm phong: ${d.seal}`));
  const card = el("details", { class: "card" }, head, body);
  if (open) card.open = true;
  return card;
}

function openViewer(url) {
  $("viewer-img").src = url;
  $("viewer").classList.remove("zoom");
  $("viewer").hidden = false;
}

function setMsg(text, isError) {
  $("msg").textContent = text;
  $("msg").className = isError ? "msg err" : "msg";
}

function clearResult() {
  imageUrls.forEach((u) => URL.revokeObjectURL(u));
  imageUrls = [];
  $("exams").replaceChildren();
  $("result").hidden = true;
}

async function lookup(raw) {
  clearResult();
  const code = normalize(raw);
  if (!code) return;
  if (!window.crypto || !crypto.subtle) {
    setMsg("Trình duyệt này không hỗ trợ. Hãy mở bằng Chrome hoặc Safari bản mới (địa chỉ https).", true);
    return;
  }
  if (!(await isValid(code))) {
    setMsg("Mã không đúng. Kiểm tra lại từng ký tự trên phiếu tra cứu.", true);
    return;
  }
  $("go").disabled = true;
  setMsg("Đang mở bài...");
  try {
    const [cfg, manifest] = await Promise.all([fetchJson("config.json"), fetchJson("exams.json")]);
    if (cfg.version !== SITE_VERSION) throw new Error("version");
    const keys = await deriveKeys(code, hexToBytes(cfg.salt), cfg.iterations);
    const results = await Promise.all((manifest.exams || []).map((e) => loadExam(keys, e).catch(() => null)));
    const found = results.filter(Boolean);
    if (!found.length) {
      setMsg("Chưa có bài nào của mã này. Có thể kỳ thi chưa được công bố, hoặc em đã được cấp mã mới.", true);
      return;
    }
    $("who-name").textContent = found[0].data.name;
    $("who-class").textContent = found[0].data.class ? `Lớp ${found[0].data.class}` : "";
    found.forEach((f, i) => $("exams").append(renderExam(f, i === 0)));
    $("result").hidden = false;
    $("code").value = "";                                  // không để mã nằm trên màn hình
    setMsg(`Tìm thấy ${found.length} kỳ thi.`);
  } catch (err) {
    setMsg("Không tải được dữ liệu. Kiểm tra mạng rồi thử lại.", true);
  } finally {
    $("go").disabled = false;
  }
}

$("form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  lookup($("code").value);
});
$("code").addEventListener("blur", () => {
  const c = normalize($("code").value);
  if (c) $("code").value = pretty(c);
});
$("logout").addEventListener("click", () => {
  clearResult();
  $("code").value = "";
  setMsg("");
  history.replaceState(null, "", location.pathname);
});
$("viewer").addEventListener("click", (ev) => {
  if (ev.target.id === "viewer-close") $("viewer").hidden = true;
  else $("viewer").classList.toggle("zoom");
});

function lookupFromLink() {
  const fromLink = normalize(decodeURIComponent(location.hash.slice(1)));
  if (fromLink) {
    history.replaceState(null, "", location.pathname);   // không để mã nằm trên thanh địa chỉ
    $("code").value = "";                                  // không hiện mã ra màn hình (chống đọc trộm)
    lookup(fromLink);
  }
}
window.addEventListener("hashchange", lookupFromLink);   // quét mã QR khác khi trang đang mở
lookupFromLink();
