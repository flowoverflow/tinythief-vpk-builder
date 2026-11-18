/* Tiny Thief VPK builder: makes a PS Vita VPK from a supplied Tiny Thief 1.2.1 XAPK.
 *
 * Plain JavaScript without libraries, as a classic script (it works from a local file:// page, where modules do not):
 * it sets globalThis.TTBuilder. It uses only what browsers and Node 22+ both have: DecompressionStream /
 * CompressionStream (deflate), crypto.subtle (SHA-256), Blob and Response. tools in test/ run the same file in Node.
 *
 * TTBuilder.build(bytes, payload, {name, log}) returns {name, parts, report}. bytes: the XAPK (a ZIP holding the APK
 * and the OBB), and nothing else: an APK alone, the OBB alone or any other file is refused with an error whose
 * .wrongFile says what it is (identify(), wrongFile()).
 *   0. the XAPK: its APK and main.57...obb found by name and unpacked;
 *   1. the APK: its stored game files under assets/ (names, sizes, CRC-32s) give the digest the loader expects
 *      (experiments/b0-rehost/src/portable/tt_byo.h), every file's data is checked against its CRC-32, and both native
 *      libraries are unpacked and checked against their SHA-256s. Any other version of the game is refused.
 *   2. the OBB: checked the same way.
 *   3. the LiveArea pictures and the start-up picture, made from the APK's own pictures (res/drawable-*: the launcher
 *      icon, the key art, the logo and the sky), as 8-bit palette PNGs (the format the Vita's LiveArea needs).
 *   4. the VPK, a ZIP (stored entries): the payload's program (eboot.bin, param.sfo; title TTHIEFBYO), the pictures,
 *      data/tinythief.apk (the APK as given), the OBB, any supplied start save and the program
 *      cache. The loader reads the APK in place and unpacks the libraries at the first start.
 * The game's files are only read; nothing is decrypted or changed. */
(function (G) {
    'use strict';

    const te = new TextEncoder();
    const utf8 = new TextDecoder('utf-8');

    // ---------------------------------------------------------------- bytes
    const CRC_TABLE = (() => {
        const t = new Uint32Array(256);
        for (let n = 0; n < 256; n++) {
            let c = n;
            for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
            t[n] = c >>> 0;
        }
        return t;
    })();
    function crc32(u8, crc) {
        let c = (crc === undefined ? 0 : crc) ^ 0xFFFFFFFF;
        for (let i = 0; i < u8.length; i++) c = CRC_TABLE[(c ^ u8[i]) & 0xff] ^ (c >>> 8);
        return (c ^ 0xFFFFFFFF) >>> 0;
    }
    function concat(parts) {
        let n = 0;
        for (const p of parts) n += p.length;
        const out = new Uint8Array(n);
        let o = 0;
        for (const p of parts) { out.set(p, o); o += p.length; }
        return out;
    }
    function cmpBytes(a, b) {
        const n = Math.min(a.length, b.length);
        for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
        return a.length - b.length;
    }
    function startsWith(a, p) {
        if (a.length < p.length) return false;
        for (let i = 0; i < p.length; i++) if (a[i] !== p[i]) return false;
        return true;
    }
    const hex8 = v => (v >>> 0).toString(16).padStart(8, '0');
    async function sha256hex(u8) {
        const d = new Uint8Array(await G.crypto.subtle.digest('SHA-256', u8));
        return Array.from(d, b => b.toString(16).padStart(2, '0')).join('');
    }
    async function through(u8, ts) {
        const s = new Blob([u8]).stream().pipeThrough(ts);
        return new Uint8Array(await new Response(s).arrayBuffer());
    }
    const inflateRaw = u8 => through(u8, new DecompressionStream('deflate-raw'));
    const inflateZlib = u8 => through(u8, new DecompressionStream('deflate'));
    const deflateZlib = u8 => through(u8, new CompressionStream('deflate'));
    function fromBase64(s) {
        const bin = G.atob(s);
        const u8 = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
        return u8;
    }

    // ---------------------------------------------------------------- ZIP reading (APK, OBB)
    function readZip(u8, label) {
        const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
        let eocd = -1;
        for (let i = u8.length - 22; i >= Math.max(0, u8.length - 22 - 65535); i--)
            if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
        if (eocd < 0) throw new Error(label + ' is not a ZIP archive (not an APK/OBB, or cut short)');
        const count = dv.getUint16(eocd + 10, true), cdOff = dv.getUint32(eocd + 16, true);
        if (count === 0xffff || cdOff === 0xffffffff) throw new Error(label + ': ZIP64 archives are not supported');
        const entries = [];
        let p = cdOff;
        for (let i = 0; i < count; i++) {
            if (p + 46 > u8.length || dv.getUint32(p, true) !== 0x02014b50) throw new Error(label + ': damaged central directory');
            const nlen = dv.getUint16(p + 28, true), xlen = dv.getUint16(p + 30, true), clen = dv.getUint16(p + 32, true);
            const nameBytes = u8.subarray(p + 46, p + 46 + nlen);
            entries.push({nameBytes, name: utf8.decode(nameBytes), method: dv.getUint16(p + 10, true), crc: dv.getUint32(p + 16, true),
                          csize: dv.getUint32(p + 20, true), usize: dv.getUint32(p + 24, true), lho: dv.getUint32(p + 42, true)});
            p += 46 + nlen + xlen + clen;
        }
        return entries;
    }
    function entryData(u8, e, label) {
        const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
        if (e.lho + 30 > u8.length || dv.getUint32(e.lho, true) !== 0x04034b50) throw new Error(label + ': damaged entry ' + e.name);
        const start = e.lho + 30 + dv.getUint16(e.lho + 26, true) + dv.getUint16(e.lho + 28, true);
        if (start + e.csize > u8.length) throw new Error(label + ' is cut short (' + e.name + ')');
        return u8.subarray(start, start + e.csize);
    }
    async function extract(u8, entries, name, label) {
        const e = entries.find(x => x.name === name);
        if (!e) return null;
        const raw = entryData(u8, e, label);
        let out;
        if (e.method === 0) out = raw;
        else if (e.method === 8) out = await inflateRaw(raw);
        else throw new Error(label + ': ' + name + ' uses compression method ' + e.method);
        if (out.length !== e.usize || crc32(out) !== e.crc) throw new Error(label + ': ' + name + ' is damaged');
        return out;
    }
    /* the loader's rule (tt_byo.h): stored, non-directory entries under prefix, sorted by name bytes, one line
     * "name\tsize\tcrc32\n" each, SHA-256 over the lines; with verify every entry's data against its CRC-32 */
    async function gameFiles(u8, entries, prefix, verify, label, progress) {
        const pre = te.encode(prefix);
        const rows = entries.filter(e => e.method === 0 && startsWith(e.nameBytes, pre) && e.nameBytes.length > pre.length &&
                                         e.nameBytes[e.nameBytes.length - 1] !== 0x2f);
        rows.sort((a, b) => cmpBytes(a.nameBytes, b.nameBytes));
        const parts = [], bad = [];
        let bytes = 0, done = 0;
        for (const e of rows) bytes += e.usize;
        for (const e of rows) {
            parts.push(e.nameBytes, te.encode('\t' + e.usize + '\t' + hex8(e.crc) + '\n'));
            if (verify) {
                if (crc32(entryData(u8, e, label)) !== e.crc) bad.push(e.name);
                done += e.usize;
                if (progress) progress(done / bytes);
            }
        }
        return {entries: rows.length, bytes, digest: await sha256hex(concat(parts)), bad};
    }

    // ---------------------------------------------------------------- PNG reading (the APK's pictures)
    const be32 = (u8, p) => ((u8[p] << 24) | (u8[p + 1] << 16) | (u8[p + 2] << 8) | u8[p + 3]) >>> 0;
    async function decodePng(u8, label) {
        const sig = [137, 80, 78, 71, 13, 10, 26, 10];
        for (let i = 0; i < 8; i++) if (u8[i] !== sig[i]) throw new Error(label + ' is not a PNG');
        let p = 8, w = 0, h = 0, bd = 0, ct = 0, il = 0, pal = null, trns = null;
        const idat = [];
        while (p + 8 <= u8.length) {
            const len = be32(u8, p), type = String.fromCharCode(u8[p + 4], u8[p + 5], u8[p + 6], u8[p + 7]);
            const data = u8.subarray(p + 8, p + 8 + len);
            if (type === 'IHDR') { w = be32(data, 0); h = be32(data, 4); bd = data[8]; ct = data[9]; il = data[12]; }
            else if (type === 'PLTE') pal = data;
            else if (type === 'tRNS') trns = data;
            else if (type === 'IDAT') idat.push(data);
            else if (type === 'IEND') break;
            p += 12 + len;
        }
        const ch = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[ct];
        if (bd !== 8 || il !== 0 || !ch || (ct === 3 && !pal)) throw new Error(label + ': unsupported PNG (depth ' + bd + ', type ' + ct + ')');
        const raw = await inflateZlib(concat(idat));
        const stride = w * ch, px = new Uint8Array(w * h * 4);
        let prev = new Uint8Array(stride), cur = new Uint8Array(stride);
        for (let y = 0; y < h; y++) {
            const f = raw[y * (stride + 1)], line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
            for (let x = 0; x < stride; x++) {
                const a = x >= ch ? cur[x - ch] : 0, b = prev[x], c = x >= ch ? prev[x - ch] : 0;
                let v = line[x];
                if (f === 1) v += a;
                else if (f === 2) v += b;
                else if (f === 3) v += (a + b) >> 1;
                else if (f === 4) {
                    const q = a + b - c, pa = Math.abs(q - a), pb = Math.abs(q - b), pc = Math.abs(q - c);
                    v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
                } else if (f !== 0) throw new Error(label + ': bad PNG filter');
                cur[x] = v & 255;
            }
            for (let x = 0; x < w; x++) {
                const o = (y * w + x) * 4;
                if (ct === 6) { px[o] = cur[x * 4]; px[o + 1] = cur[x * 4 + 1]; px[o + 2] = cur[x * 4 + 2]; px[o + 3] = cur[x * 4 + 3]; }
                else if (ct === 2) { px[o] = cur[x * 3]; px[o + 1] = cur[x * 3 + 1]; px[o + 2] = cur[x * 3 + 2]; px[o + 3] = 255; }
                else if (ct === 3) { const i = cur[x]; px[o] = pal[i * 3]; px[o + 1] = pal[i * 3 + 1]; px[o + 2] = pal[i * 3 + 2]; px[o + 3] = trns && i < trns.length ? trns[i] : 255; }
                else if (ct === 0) { px[o] = px[o + 1] = px[o + 2] = cur[x]; px[o + 3] = 255; }
                else { px[o] = px[o + 1] = px[o + 2] = cur[x * 2]; px[o + 3] = cur[x * 2 + 1]; }
            }
            const t = prev; prev = cur; cur = t;
        }
        return {w, h, px};
    }

    // ---------------------------------------------------------------- pictures: scale, crop, compose
    function blank(w, h, rgba) {
        const px = new Uint8Array(w * h * 4);
        if (rgba) for (let i = 0; i < px.length; i += 4) { px[i] = rgba[0]; px[i + 1] = rgba[1]; px[i + 2] = rgba[2]; px[i + 3] = rgba[3]; }
        return {w, h, px};
    }
    /* premultiplied resampling: area average when shrinking, bilinear when enlarging */
    function resize(img, W, H) {
        const {w, h, px} = img, out = new Uint8Array(W * H * 4);
        const sx = w / W, sy = h / H, acc = new Float64Array(4);
        for (let y = 0; y < H; y++) {
            for (let x = 0; x < W; x++) {
                acc.fill(0);
                let wsum = 0;
                if (sx >= 1 && sy >= 1) {
                    const x0 = x * sx, x1 = x0 + sx, y0 = y * sy, y1 = y0 + sy;
                    for (let yy = Math.floor(y0); yy < Math.min(h, Math.ceil(y1)); yy++) {
                        const wy = Math.min(yy + 1, y1) - Math.max(yy, y0);
                        for (let xx = Math.floor(x0); xx < Math.min(w, Math.ceil(x1)); xx++) {
                            const wt = wy * (Math.min(xx + 1, x1) - Math.max(xx, x0)), o = (yy * w + xx) * 4, a = px[o + 3] / 255;
                            acc[0] += px[o] * a * wt; acc[1] += px[o + 1] * a * wt; acc[2] += px[o + 2] * a * wt; acc[3] += px[o + 3] * wt;
                            wsum += wt;
                        }
                    }
                } else {
                    const fx = Math.min(Math.max((x + 0.5) * sx - 0.5, 0), w - 1), fy = Math.min(Math.max((y + 0.5) * sy - 0.5, 0), h - 1);
                    const x0 = Math.floor(fx), y0 = Math.floor(fy), x1 = Math.min(x0 + 1, w - 1), y1 = Math.min(y0 + 1, h - 1);
                    const tx = fx - x0, ty = fy - y0;
                    for (const [xx, yy, wt] of [[x0, y0, (1 - tx) * (1 - ty)], [x1, y0, tx * (1 - ty)], [x0, y1, (1 - tx) * ty], [x1, y1, tx * ty]]) {
                        const o = (yy * w + xx) * 4, a = px[o + 3] / 255;
                        acc[0] += px[o] * a * wt; acc[1] += px[o + 1] * a * wt; acc[2] += px[o + 2] * a * wt; acc[3] += px[o + 3] * wt;
                        wsum += wt;
                    }
                }
                const o = (y * W + x) * 4, A = acc[3] / wsum;
                out[o + 3] = Math.round(A);
                for (let c = 0; c < 3; c++) out[o + c] = A > 0 ? Math.min(255, Math.round(acc[c] / wsum / (A / 255))) : 0;
            }
        }
        return {w: W, h: H, px: out};
    }
    function crop(img, x0, y0, W, H) {
        const out = blank(W, H);
        for (let y = 0; y < H; y++) out.px.set(img.px.subarray(((y0 + y) * img.w + x0) * 4, ((y0 + y) * img.w + x0 + W) * 4), y * W * 4);
        return out;
    }
    /* scaled to cover W x H, never stretched, then cropped at the anchor (0 = left/top edge, 1 = right/bottom edge) */
    function cover(img, W, H, ax, ay) {
        const s = Math.max(W / img.w, H / img.h), rw = Math.max(W, Math.round(img.w * s)), rh = Math.max(H, Math.round(img.h * s));
        return crop(resize(img, rw, rh), Math.round((rw - W) * ax), Math.round((rh - H) * ay), W, H);
    }
    function fit(img, W, H) {
        const s = Math.min(W / img.w, H / img.h);
        return resize(img, Math.max(1, Math.round(img.w * s)), Math.max(1, Math.round(img.h * s)));
    }
    function over(dst, src, x0, y0) {   /* src composited over dst (straight alpha) */
        for (let y = 0; y < src.h; y++) for (let x = 0; x < src.w; x++) {
            const X = x0 + x, Y = y0 + y;
            if (X < 0 || Y < 0 || X >= dst.w || Y >= dst.h) continue;
            const s = (y * src.w + x) * 4, d = (Y * dst.w + X) * 4, a = src.px[s + 3] / 255, b = dst.px[d + 3] / 255, oa = a + b * (1 - a);
            for (let c = 0; c < 3; c++) dst.px[d + c] = oa > 0 ? Math.round((src.px[s + c] * a + dst.px[d + c] * b * (1 - a)) / oa) : 0;
            dst.px[d + 3] = Math.round(oa * 255);
        }
        return dst;
    }
    function opaque(img) { return over(blank(img.w, img.h, [0, 0, 0, 255]), img, 0, 0); }

    // ---------------------------------------------------------------- PNG writing: 8-bit palette (LiveArea) and RGBA
    function quantize(img, n) {   /* median cut over 5-bit colour cells, then Floyd-Steinberg dithering */
        const {w, h, px} = img, cnt = new Float64Array(32768), sum = new Float64Array(32768 * 3);
        for (let i = 0; i < px.length; i += 4) {
            const k = ((px[i] >> 3) << 10) | ((px[i + 1] >> 3) << 5) | (px[i + 2] >> 3);
            cnt[k]++; sum[k * 3] += px[i]; sum[k * 3 + 1] += px[i + 1]; sum[k * 3 + 2] += px[i + 2];
        }
        const cells = [];
        for (let k = 0; k < 32768; k++) if (cnt[k]) cells.push(k);
        const boxes = [cells];
        const comp = (k, a) => a === 0 ? k >> 10 : a === 1 ? (k >> 5) & 31 : k & 31;
        while (boxes.length < n) {
            let bi = -1, best = 0, axis = 0;
            boxes.forEach((b, i) => {
                if (b.length < 2) return;
                const mn = [31, 31, 31], mx = [0, 0, 0];
                let c = 0;
                for (const k of b) { for (let a = 0; a < 3; a++) { const v = comp(k, a); if (v < mn[a]) mn[a] = v; if (v > mx[a]) mx[a] = v; } c += cnt[k]; }
                for (let a = 0; a < 3; a++) { const score = (mx[a] - mn[a]) * c; if (score > best) { best = score; bi = i; axis = a; } }
            });
            if (bi < 0) break;
            const b = boxes[bi].sort((p, q) => comp(p, axis) - comp(q, axis));
            let total = 0, acc = 0, cut = b.length - 1;
            for (const k of b) total += cnt[k];
            for (let i = 0; i < b.length - 1; i++) { acc += cnt[b[i]]; if (acc >= total / 2) { cut = i + 1; break; } }
            boxes.splice(bi, 1, b.slice(0, cut), b.slice(cut));
        }
        const pal = new Uint8Array(boxes.length * 3);
        boxes.forEach((b, i) => {
            let c = 0, r = 0, g = 0, bl = 0;
            for (const k of b) { c += cnt[k]; r += sum[k * 3]; g += sum[k * 3 + 1]; bl += sum[k * 3 + 2]; }
            pal[i * 3] = Math.round(r / c); pal[i * 3 + 1] = Math.round(g / c); pal[i * 3 + 2] = Math.round(bl / c);
        });
        const near = new Int16Array(32768).fill(-1), np = boxes.length;
        const nearest = (r, g, b) => {
            const k = ((r >> 3) << 10) | ((g >> 3) << 5) | (b >> 3);
            if (near[k] >= 0) return near[k];
            let bi = 0, bd = Infinity;
            for (let i = 0; i < np; i++) {
                const dr = pal[i * 3] - r, dg = pal[i * 3 + 1] - g, db = pal[i * 3 + 2] - b, d = dr * dr * 2 + dg * dg * 4 + db * db * 3;
                if (d < bd) { bd = d; bi = i; }
            }
            return (near[k] = bi);
        };
        const err = new Float32Array(w * h * 3);
        for (let i = 0; i < w * h; i++) { err[i * 3] = px[i * 4]; err[i * 3 + 1] = px[i * 4 + 1]; err[i * 3 + 2] = px[i * 4 + 2]; }
        const idx = new Uint8Array(w * h);
        const push = (x, y, er, eg, eb, f) => {
            if (x < 0 || x >= w || y >= h) return;
            const o = (y * w + x) * 3;
            err[o] += er * f; err[o + 1] += eg * f; err[o + 2] += eb * f;
        };
        for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
            const o = (y * w + x) * 3;
            const r = Math.min(255, Math.max(0, Math.round(err[o]))), g = Math.min(255, Math.max(0, Math.round(err[o + 1]))),
                  b = Math.min(255, Math.max(0, Math.round(err[o + 2])));
            const i = nearest(r, g, b);
            idx[y * w + x] = i;
            const er = r - pal[i * 3], eg = g - pal[i * 3 + 1], eb = b - pal[i * 3 + 2];
            push(x + 1, y, er, eg, eb, 7 / 16); push(x - 1, y + 1, er, eg, eb, 3 / 16); push(x, y + 1, er, eg, eb, 5 / 16); push(x + 1, y + 1, er, eg, eb, 1 / 16);
        }
        return {pal, idx};
    }
    function chunk(type, data) {
        const head = new Uint8Array(8), tail = new Uint8Array(4);
        new DataView(head.buffer).setUint32(0, data.length);
        head.set(te.encode(type), 4);
        new DataView(tail.buffer).setUint32(0, crc32(concat([head.subarray(4), data])));
        return concat([head, data, tail]);
    }
    async function encodePng(w, h, colourType, rows /* (y) => Uint8Array of one row */, pal) {
        const bpp = colourType === 3 ? 1 : 4, stride = w * bpp, raw = new Uint8Array(h * (stride + 1));
        let prev = new Uint8Array(stride);
        for (let y = 0; y < h; y++) {
            const row = rows(y), o = y * (stride + 1);
            if (colourType === 3) { raw[o] = 0; raw.set(row, o + 1); }
            else { raw[o] = 2; for (let x = 0; x < stride; x++) raw[o + 1 + x] = (row[x] - prev[x]) & 255; }   /* "up" filter */
            prev = row;
        }
        const ihdr = new Uint8Array(13), dv = new DataView(ihdr.buffer);
        dv.setUint32(0, w); dv.setUint32(4, h); ihdr[8] = 8; ihdr[9] = colourType;
        const parts = [new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr)];
        if (pal) parts.push(chunk('PLTE', pal));
        parts.push(chunk('IDAT', await deflateZlib(raw)), chunk('IEND', new Uint8Array(0)));
        return concat(parts);
    }
    async function palettePng(img) {
        const q = quantize(opaque(img), 256);
        return encodePng(img.w, img.h, 3, y => q.idx.subarray(y * img.w, (y + 1) * img.w), q.pal);
    }
    async function rgbaPng(img) { const o = opaque(img); return encodePng(o.w, o.h, 6, y => o.px.subarray(y * o.w * 4, (y + 1) * o.w * 4)); }

    // ---------------------------------------------------------------- ZIP writing (the VPK)
    function zipStored(files) {   /* [{name, data}] -> array of Uint8Array parts; stored entries, UTF-8 names */
        const parts = [], central = [];
        let off = 0;
        for (const f of files) {
            const name = te.encode(f.name), crc = crc32(f.data), lh = new Uint8Array(30), dv = new DataView(lh.buffer);
            dv.setUint32(0, 0x04034b50, true); dv.setUint16(4, 20, true); dv.setUint16(6, 0x0800, true); dv.setUint16(8, 0, true);
            dv.setUint16(10, 0, true); dv.setUint16(12, 0x21, true); dv.setUint32(14, crc, true);
            dv.setUint32(18, f.data.length, true); dv.setUint32(22, f.data.length, true); dv.setUint16(26, name.length, true);
            const ch = new Uint8Array(46), cv = new DataView(ch.buffer);
            cv.setUint32(0, 0x02014b50, true); cv.setUint16(4, 20, true); cv.setUint16(6, 20, true); cv.setUint16(8, 0x0800, true);
            cv.setUint16(14, 0x21, true); cv.setUint32(16, crc, true); cv.setUint32(20, f.data.length, true);
            cv.setUint32(24, f.data.length, true); cv.setUint16(28, name.length, true); cv.setUint32(42, off, true);
            parts.push(lh, name, f.data);
            central.push(ch, name);
            off += 30 + name.length + f.data.length;
        }
        if (off > 0xffffffff) throw new Error('the VPK would be over 4 GB');
        let csize = 0;
        for (const c of central) csize += c.length;
        const end = new Uint8Array(22), ev = new DataView(end.buffer);
        ev.setUint32(0, 0x06054b50, true); ev.setUint16(8, files.length, true); ev.setUint16(10, files.length, true);
        ev.setUint32(12, csize, true); ev.setUint32(16, off, true);
        return parts.concat(central, [end]);
    }

    const TEMPLATE = '<?xml version="1.0" encoding="utf-8"?>\r\n\r\n<livearea style="a1" format-ver="01.00" content-rev="1">\r\n' +
        '\t<livearea-background>\r\n\t\t<image>bg.png</image>\r\n\t</livearea-background>\r\n\r\n' +
        '\t<gate>\r\n\t\t<startup-image>startup.png</startup-image>\r\n\t</gate>\r\n</livearea>\r\n';

    /* the APK's own pictures: a picture under any res/drawable* folder, the largest copy */
    function findPicture(entries, file) {
        const hits = entries.filter(e => /^res\/drawable[^/]*\//.test(e.name) && e.name.endsWith('/' + file));
        hits.sort((a, b) => b.usize - a.usize);
        return hits.length ? hits[0].name : null;
    }

    /* The pictures the VPK carries. palette: an 8-bit palette PNG, the format the LiveArea needs; else RGBA (the
     * start-up picture, read by the program with stb_image). */
    const SLOTS = [
        {id: 'icon0', label: 'Bubble icon', where: 'the home screen', w: 128, h: 128, path: 'sce_sys/icon0.png', palette: true},
        {id: 'bg', label: 'LiveArea background', where: 'the LiveArea', w: 840, h: 500, path: 'sce_sys/livearea/contents/bg.png', palette: true},
        {id: 'startup', label: 'Start button', where: 'the LiveArea', w: 280, h: 158, path: 'sce_sys/livearea/contents/startup.png', palette: true},
        {id: 'pic0', label: 'Boot picture', where: 'shown by the system as the app opens', w: 960, h: 544, path: 'sce_sys/pic0.png', palette: true},
        {id: 'splash', label: 'Start-up picture', where: 'shown while the game loads', w: 960, h: 544, path: 'assets/splash.png', palette: false},
    ];
    const slotById = id => SLOTS.find(s => s.id === id);
    /* any picture made to fill a slot: scaled to cover it, never stretched, cropped from the centre */
    function fitToSlot(img, slot) { return img.w === slot.w && img.h === slot.h ? img : cover(img, slot.w, slot.h, 0.5, 0.5); }
    function encodeSlot(slot, img) { return slot.palette ? palettePng(img) : rgbaPng(img); }

    /* What the user's file is, from its content (the name only tells an OBB from another ZIP):
     *   'xapk'     a ZIP without AndroidManifest.xml at its root that holds an .apk;
     *   'apk'      an APK (AndroidManifest.xml at its root);
     *   'obb'      the game's OBB (named .obb, or a ZIP with exactly the OBB's file count and no .apk);
     *   'not-zip'  not a ZIP (or cut short), and 'other' any other ZIP. */
    function identify(bytes, name, ex) {
        let entries;
        try { entries = readZip(bytes, 'The file'); } catch (err) { return {what: 'not-zip'}; }
        if (entries.some(e => e.name === 'AndroidManifest.xml')) return {what: 'apk', entries};
        if (entries.some(e => /\.apk$/i.test(e.name))) return {what: 'xapk', entries};
        const files = entries.filter(e => !e.name.endsWith('/')).length;
        if (/\.obb$/i.test(name || '') || (ex && files === ex.obb.entries)) return {what: 'obb', entries};
        return {what: 'other', entries};
    }

    /* The refusal for a file that is not the XAPK: err.wrongFile names what it is, err.title says it in a few words. */
    function wrongFile(what, ex) {
        const T = {
            'apk': ['That is an APK, not the XAPK',
                    'You dropped the APK on its own. This builder needs the Tiny Thief XAPK (a .xapk file), which holds the ' +
                    'APK together with the game\'s data file (the OBB); the VPK needs both. Drop the XAPK instead.'],
            'obb': ['That is the OBB, not the XAPK',
                    'You dropped the game\'s data file (the OBB) on its own. This builder needs the Tiny Thief XAPK (a .xapk ' +
                    'file), which holds the APK and this OBB together. Drop the XAPK instead.'],
            'xapk-no-obb': ['This XAPK has no OBB inside',
                    'This XAPK holds an APK but not the game\'s data file (' + (ex ? ex.obbName : 'the OBB') + '), so it is ' +
                    'incomplete. Use a full Tiny Thief 1.2.1 XAPK.'],
            'many': ['Drop one file only',
                    'This builder takes one file: the Tiny Thief XAPK (a .xapk file). Not the APK and OBB separately.'],
            'not-zip': ['That is not an XAPK',
                    'That file is not an XAPK (it is not a ZIP archive, or it was cut short). Drop the Tiny Thief XAPK (a .xapk file).'],
            'other': ['That is not an XAPK',
                    'That file holds no APK, so it is not an XAPK. Drop the Tiny Thief XAPK (a .xapk file).']
        }[what] || ['That is not an XAPK', 'Drop the Tiny Thief XAPK (a .xapk file).'];
        const err = new Error(T[1]);
        err.wrongFile = what;
        err.title = T[0];
        return err;
    }

    /* Step 1: the user's XAPK checked, and the pictures made from its APK's own (images: RGBA, pngs: as packed).
     * opts.name: the file's name (it tells an OBB from another ZIP in the refusal). */
    async function prepare(apk, payload, opts) {
        opts = opts || {};
        const log = opts.log || (() => {});
        const progress = opts.progress || (() => {});
        const ex = payload.expect, report = {};
        if (!(apk instanceof Uint8Array)) apk = new Uint8Array(apk);

        /* The XAPK only: one ZIP holding the APK and, under Android/obb/..., the OBB. Anything else is refused with a
         * WrongFile error saying what the file is (an APK, the OBB, something else). The APK and the OBB are found by
         * name, wherever they sit, and checked below: only Tiny Thief 1.2.1's exact game files and libraries pass,
         * whoever packed the XAPK. */
        const kind = identify(apk, opts.name, ex);
        if (kind.what !== 'xapk') throw wrongFile(kind.what, ex);
        const top = kind.entries;
        const apks = top.filter(e => /\.apk$/i.test(e.name));
        const rank = e => (/com\.roviostars\.tinythief/i.test(e.name) ? 2 : /(^|\/)base\.apk$/i.test(e.name) ? 1 : 0);
        apks.sort((a, b) => rank(b) - rank(a) || b.usize - a.usize);
        const ob = top.find(e => e.name.split('/').pop() === ex.obbName);
        if (!ob) throw wrongFile('xapk-no-obb', ex);
        log('Reading the XAPK (' + (apk.length / 1048576).toFixed(1) + ' MB): its APK is ' + apks[0].name + ', its OBB ' + ob.name + '.');
        const xapk = apk;
        const obb = await extract(xapk, top, ob.name, 'The XAPK');
        apk = await extract(xapk, top, apks[0].name, 'The XAPK');

        log('Reading the APK (' + (apk.length / 1048576).toFixed(1) + ' MB)...');
        const entries = readZip(apk, 'The APK');
        const g = await gameFiles(apk, entries, ex.apk.prefix, true, 'The APK', f => progress('Checking the APK', f));
        report.apk = g;
        if (g.entries !== ex.apk.entries || g.bytes !== ex.apk.bytes || g.digest !== ex.apk.digest)
            throw new Error('This APK is not Tiny Thief 1.2.1 for Android (' + g.entries + ' game files, ' + ex.apk.entries +
                            ' expected). Only that version is supported.');
        if (g.bad.length) throw new Error('The APK is damaged (' + g.bad.length + ' file(s), first ' + g.bad[0] + '): copy it again.');
        log('APK: Tiny Thief 1.2.1, ' + g.entries + ' game files checked.');
        for (const lib of ex.libs) {
            const data = await extract(apk, entries, lib.entry, 'The APK');
            if (!data) throw new Error('This APK has no ' + lib.entry + ': it is not the supported version.');
            const h = await sha256hex(data);
            if (data.length !== lib.size || h !== lib.sha256) throw new Error(lib.entry + ' in this APK is not the supported version.');
            log('Library ' + lib.file + ': ' + (data.length / 1048576).toFixed(1) + ' MB, checked.');
        }

        const oe = readZip(obb, 'The OBB');
        const og = await gameFiles(obb, oe, ex.obb.prefix, true, 'The OBB', f => progress('Checking the OBB', f));
        report.obb = og;
        if (og.entries !== ex.obb.entries || og.bytes !== ex.obb.bytes || og.digest !== ex.obb.digest)
            throw new Error('The OBB in this XAPK is not the one Tiny Thief 1.2.1 uses (' + ex.obbName + ').');
        if (og.bad.length) throw new Error('The OBB in this XAPK is damaged (' + og.bad[0] + '): copy the XAPK again.');
        log('OBB: ' + og.entries + ' game files checked.');

        log('Making the LiveArea pictures from the APK...');
        const pic = async file => {
            const name = findPicture(entries, file);
            if (!name) throw new Error('The APK has no ' + file + ' picture.');
            return decodePng(await extract(apk, entries, name, 'The APK'), name);
        };
        const icon = await pic('icon.png'), art = await pic('tinythief.png'), logo = await pic('tt_logo.png'), sky = await pic('tt_loading_bg.png');
        const icon0 = resize(icon, 128, 128);
        const bg = cover(art, 840, 500, 0.5, 0.4);
        const startup = cover(sky, 280, 158, 0.5, 0.5);
        const lg = fit(logo, 250, 140);
        over(startup, lg, Math.round((280 - lg.w) / 2), Math.round((158 - lg.h) / 2));
        const wide = cover(art, 960, 544, 0.5, 0.35);
        const images = {icon0, bg, startup, pic0: wide, splash: wide}, pngs = {};
        for (const s of SLOTS) pngs[s.id] = await encodeSlot(s, images[s.id]);
        return {apk, obb, images, pngs, report};
    }

    /* Step 2: the VPK from what prepare() made; prep.pngs may have been replaced in between (the page's own pictures). */
    async function assemble(prep, payload, opts) {
        opts = opts || {};
        const log = opts.log || (() => {});
        const ex = payload.expect, report = prep.report;
        const pictures = {};
        for (const s of SLOTS) pictures[s.path] = prep.pngs[s.id];
        report.pictures = Object.fromEntries(Object.entries(pictures).map(([k, v]) => [k, v.length]));
        const apk = prep.apk, obb = prep.obb;

        const files = [
            {name: 'sce_sys/param.sfo', data: fromBase64(payload.paramSfo)},
            {name: 'eboot.bin', data: fromBase64(payload.eboot)},
        ];
        for (const [name, data] of Object.entries(pictures)) files.push({name, data});
        files.push({name: 'sce_sys/livearea/contents/template.xml', data: te.encode(TEMPLATE)});
        files.push({name: 'data/tinythief.apk', data: apk});
        files.push({name: 'data/' + ex.obbName, data: obb});
        for (const [name, b64] of Object.entries(payload.startSave)) files.push({name: 'data/start-save/files/' + name, data: fromBase64(b64)});
        for (const [name, b64] of Object.entries(payload.cache)) files.push({name: 'data/cache/' + name, data: fromBase64(b64)});
        log('Writing the VPK (' + files.length + ' files)...');
        const parts = zipStored(files);
        let size = 0;
        for (const p of parts) size += p.length;
        report.vpk = {files: files.map(f => f.name), size};
        log('Done: TinyThief.vpk, ' + (size / 1048576).toFixed(1) + ' MB (program ' + payload.build + ').');
        return {name: 'TinyThief.vpk', parts, report};
    }

    async function build(xapk, payload, opts) { return assemble(await prepare(xapk, payload, opts), payload, opts); }

    G.TTBuilder = {build, prepare, assemble, identify, wrongFile, SLOTS, slotById, fitToSlot, encodeSlot, crc32, readZip, gameFiles, decodePng,
                   encodePng, quantize, resize, cover, zipStored, sha256hex};
})(typeof globalThis !== 'undefined' ? globalThis : this);
