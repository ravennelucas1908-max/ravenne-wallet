// Generates ravenne.ico — a clean geometric "wing" mark on a purple rounded square.
// Pure Node (no canvas lib): manual RGBA buffer → PNG (zlib) → ICO via png-to-ico.
import fs from "node:fs";
import zlib from "node:zlib";
import pngToIco from "png-to-ico";

const S = 256;
const px = Buffer.alloc(S * S * 4, 0);

// helpers
const inRounded = (x, y, r) => {
  const cx = Math.min(Math.max(x, r), S - 1 - r), cy = Math.min(Math.max(y, r), S - 1 - r);
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r || (x >= r && x <= S - 1 - r) || (y >= r && y <= S - 1 - r);
};
const set = (x, y, [r, g, b, a]) => { const i = (y * S + x) * 4; px[i] = r; px[i + 1] = g; px[i + 2] = b; px[i + 3] = a; };

for (let y = 0; y < S; y++) {
  for (let x = 0; x < S; x++) {
    if (!inRounded(x, y, 56)) continue;
    // vertical purple gradient #2a1a4a → #7c3aed
    const t = y / S;
    const bg = [42 + t * 82, 26 + t * 32, 74 + t * 131, 255]; // → (124,58,237)
    // three diagonal white "wing" stripes: centered bands across the diagonal
    const d = (x + y) / 2;                       // 0..255 along the diagonal
    const w1 = Math.abs(d - 118), w2 = Math.abs(d - 146), w3 = Math.abs(d - 174);
    const soft = w => Math.max(0, 1 - w / 9);    // ~9px soft edge
    const a = Math.max(soft(w1) * 0.95, soft(w2) * 0.62, soft(w3) * 0.30);
    // fade stripes near the corners so they feel "swept"
    const edge = Math.min(1, Math.min(x, y, S - 1 - x, S - 1 - y) / 34);
    const alpha = a * (0.35 + 0.65 * edge);
    const out = [0, 1, 2].map(i => Math.round(bg[i] * (1 - alpha) + 255 * alpha));
    set(x, y, [...out, 255]);
  }
}

// encode PNG (manual: IHDR + IDAT + IEND)
const crcTable = [...Array(256)].map((_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = buf => { let c = 0xFFFFFFFF; for (const b of buf) c = crcTable[(c ^ b) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; };
const chunk = (type, data) => {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
};
const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(S, 0); ihdr.writeUInt32BE(S, 4);
ihdr[8] = 8; ihdr[9] = 6; // 8-bit RGBA
const rows = [...Array(S)].map((_, y) => Buffer.concat([Buffer.from([0]), px.subarray(y * S * 4, (y + 1) * S * 4)]));
const raw = Buffer.concat(rows);
const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
  chunk("IHDR", ihdr), chunk("IDAT", zlib.deflateSync(raw)), chunk("IEND", Buffer.alloc(0)),
]);
fs.writeFileSync("ravenne-256.png", png);
await pngToIco([fs.readFileSync("ravenne-256.png")]).then(buf => fs.writeFileSync("ravenne.ico", buf));
console.log("ravenne.ico written (256×256)");
