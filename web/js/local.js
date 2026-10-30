/* 纯前端后端替身：在静态托管（GitHub Pages）环境下复刻后端工具能力 */
(function () {
  'use strict';

  const NS = (window.NS = window.NS || {});

  /* ---------------------------------------------------------------- 常量 */

  const PROXIES = [
    (u) => 'https://api.allorigins.win/raw?url=' + encodeURIComponent(u),
    (u) => 'https://api.codetabs.com/v1/proxy?quest=' + encodeURIComponent(u),
    (u) => 'https://xmokyimajkzuvbzbyqqb.supabase.co/functions/v1/site-tools?action=fetch&url=' + encodeURIComponent(u),
    (u) => 'https://corsproxy.io/?url=' + encodeURIComponent(u),
  ];

  const DOH_RESOLVERS = {
    alidns: ['https://dns.alidns.com/resolve', '阿里 DNS (223.5.5.5)'],
    cloudflare: ['https://cloudflare-dns.com/dns-query', 'Cloudflare (1.1.1.1)'],
    google: ['https://dns.google/resolve', 'Google (8.8.8.8)'],
  };

  const DNS_TYPE_NAMES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
    28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 43: 'DS', 46: 'RRSIG', 48: 'DNSKEY',
    52: 'TLSA', 65: 'HTTPS', 257: 'CAA',
  };

  const ALL_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA'];

  const SECURITY_HEADERS = [
    ['strict-transport-security', 'HSTS 强制加密传输', 'high'],
    ['content-security-policy', 'CSP 内容安全策略', 'high'],
    ['x-content-type-options', '禁止 MIME 类型嗅探', 'mid'],
    ['x-frame-options', '防点击劫持', 'mid'],
    ['referrer-policy', 'Referrer 泄露控制', 'low'],
    ['permissions-policy', '浏览器特性权限控制', 'low'],
    ['cross-origin-opener-policy', '跨源窗口隔离', 'low'],
  ];

  const NON_HTML_EXT = /\.(png|jpe?g|gif|webp|svg|bmp|ico|woff2?|ttf|otf|eot|css|js|mp4|webm|ogg|mp3|wav|m4a|m4v|pdf|zip|gz|rar|7z|exe|apk|dmg|docx?|xlsx?|pptx?|tar)(\?|$)/i;

  const TIMEOUT = 9000;

  /* ---------------------------------------------------------------- 基础工具 */

  function err(message) {
    const e = new Error(message);
    e.name = 'ApiError';
    return e;
  }

  function normalizeUrl(raw) {
    let value = String(raw || '').trim();
    if (!value) throw err('请输入网址');
    if (!/^https?:\/\//i.test(value)) value = 'https://' + value.replace(/^\/+/, '');
    const u = new URL(value);
    if (!u.hostname) throw err('网址缺少主机名');
    return u.href;
  }

  function hostOf(url) {
    try { return new URL(url).hostname; } catch (e) { return ''; }
  }

  function filenameOf(url) {
    try {
      const path = new URL(url).pathname || '';
      const name = decodeURIComponent(path.split('/').pop() || '');
      return name || 'index';
    } catch (e) { return 'index'; }
  }

  function nowIso() { return new Date().toISOString(); }

  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

  /* 有限并发池：比串行快几倍，又不会一次打爆代理 */
  async function pool(list, worker, size) {
    let cursor = 0;
    const width = Math.min(size || 4, list.length);
    const runners = [];
    for (let i = 0; i < width; i += 1) {
      runners.push((async () => {
        while (cursor < list.length) {
          const idx = cursor;
          cursor += 1;
          await worker(list[idx], idx);
        }
      })());
    }
    await Promise.all(runners);
  }

  /* ---------------------------------------------------------------- 代理抓取 */

  /* 顺序换代理，不做并发竞速：
     并发竞速会让一次页面抓取瞬间打出几十个请求，代理站直接限流，反而全挂。
     但会记住上次成功的代理，下次先试它，正常情况下每个资源只发一个请求。 */
  let preferredProxy = null;

  function tryProxy(mk, url, asBinary) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT);
    const started = performance.now();
    return fetch(mk(url), { signal: ctrl.signal, cache: 'no-store' })
      .then(async (resp) => {
        clearTimeout(timer);
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const data = asBinary ? await resp.arrayBuffer() : await resp.text();
        const size = asBinary ? data.byteLength : data.length;
        if (size < 30) throw new Error('空内容');
        return { data, size, ms: Math.round(performance.now() - started) };
      })
      .catch((e) => {
        clearTimeout(timer);
        throw (e && e.name === 'AbortError' ? new Error('超时') : e);
      });
  }

  async function fetchViaProxy(url, asBinary) {
    const errors = [];
    const order = preferredProxy === null
      ? PROXIES.map((_, i) => i)
      : [preferredProxy].concat(PROXIES.map((_, i) => i).filter((i) => i !== preferredProxy));
    /* 每个请求最多试 3 个代理：全试会拖很久，也不至于只认一个 */
    for (let k = 0; k < order.length && k < 3; k += 1) {
      const i = order[k];
      try {
        const got = await tryProxy(PROXIES[i], url, asBinary);
        preferredProxy = i;
        return got;
      } catch (e) {
        errors.push('#' + (i + 1) + ' ' + e.message);
      }
    }
    throw err('代理全部失败（' + errors.join(' / ') + '）');
  }

  /* 判断目标 http/https 是否可达：opaque 请求只要不抛错即视为连通 */
  async function reachable(url) {
    const started = performance.now();
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 8000);
      await fetch(url, { mode: 'no-cors', signal: ctrl.signal, cache: 'no-store', redirect: 'follow' });
      clearTimeout(timer);
      return { open: true, ms: Math.round(performance.now() - started) };
    } catch (e) {
      return { open: false, ms: Math.round(performance.now() - started), error: '无法连接（可能是网络/DNS/证书问题）' };
    }
  }

  /* ---------------------------------------------------------------- DNS over HTTPS */

  async function dohQuery(name, rtype, resolverKey) {
    const entry = DOH_RESOLVERS[resolverKey];
    if (!entry) throw err('未知解析器：' + resolverKey);
    const url = entry[0] + '?name=' + encodeURIComponent(name) + '&type=' + encodeURIComponent(rtype);
    let resp;
    try {
      resp = await fetch(url, { headers: { Accept: 'application/dns-json' }, cache: 'no-store' });
    } catch (e) {
      throw err('解析器不可达（可能被网络拦截）');
    }
    if (!resp.ok) throw err('解析器返回 HTTP ' + resp.status);
    let data;
    try { data = await resp.json(); } catch (e) { throw err('解析器返回内容无法解析'); }
    const records = [];
    (data.Answer || []).forEach((a) => {
      records.push({
        type: DNS_TYPE_NAMES[a.type] || String(a.type),
        name: String(a.name || name).replace(/\.$/, ''),
        data: String(a.data === undefined ? '' : a.data),
        ttl: a.TTL || 0,
      });
    });
    if (!records.length) {
      (data.Authority || []).forEach((a) => {
        records.push({
          type: DNS_TYPE_NAMES[a.type] || String(a.type),
          name: String(a.name || name).replace(/\.$/, ''),
          data: String(a.data === undefined ? '' : a.data),
          ttl: a.TTL || 0,
        });
      });
    }
    return records;
  }

  function isIp(value) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(value) || /^[0-9a-f:]+$/i.test(value) && value.indexOf(':') >= 0;
  }

  async function dnsLookup(raw, rtype, resolver) {
    const target = String(raw || '').trim().replace(/https?:\/\//, '').split('/')[0];
    if (!target || target.indexOf(' ') >= 0) throw err('域名格式不正确');
    const reverse = isIp(target);
    const name = reverse ? target : target.replace(/\.$/, '');
    const key = Object.prototype.hasOwnProperty.call(DOH_RESOLVERS, resolver) ? resolver : 'cloudflare';
    const wanted = reverse ? ['PTR'] : (String(rtype || 'ALL').toUpperCase() === 'ALL' ? ALL_TYPES.slice() : [String(rtype).toUpperCase()]);

    const started = performance.now();
    const records = [];
    const errors = [];

    const results = await Promise.all(wanted.map((kind) =>
      dohQuery(name, kind, key).then((r) => ({ kind, r, e: null })).catch((e) => ({ kind, r: [], e }))));

    results.forEach((item) => {
      if (item.e) errors.push(item.kind + ': ' + (item.e.message || '查询失败'));
      else records.push.apply(records, item.r);
    });

    const order = {};
    wanted.forEach((k, i) => { order[k] = i; });
    records.sort((a, b) => {
      const oa = order[a.type] === undefined ? 99 : order[a.type];
      const ob = order[b.type] === undefined ? 99 : order[b.type];
      if (oa !== ob) return oa - ob;
      return a.data.localeCompare(b.data);
    });

    const types = Array.from(new Set(records.map((r) => r.type))).sort();
    return {
      input: raw,
      domain: target,
      type: reverse ? 'PTR' : String(rtype || 'ALL').toUpperCase(),
      resolver: key,
      resolverLabel: DOH_RESOLVERS[key][1],
      fallback: '',
      timestamp: nowIso(),
      queryMs: Math.round(performance.now() - started),
      records,
      summary: {
        total: records.length,
        types,
        hasA: types.indexOf('A') >= 0,
        hasAAAA: types.indexOf('AAAA') >= 0,
        hasMX: types.indexOf('MX') >= 0,
        hasTXT: types.indexOf('TXT') >= 0,
        hasNS: types.indexOf('NS') >= 0,
      },
      errors,
    };
  }

  /* ---------------------------------------------------------------- 解码套件（复刻后端 deep_mine） */

  const PATH_RE_SRC = '(?:/|\\.{1,2}/)[^\\s"\'`<>]+?\\.(?:png|jpe?g|gif|webp|svg|bmp|ico|avif|woff2?|ttf|otf|eot|css|m?js|mp4|webm|ogv|m4v|mov|mp3|wav|m4a|flac|aac|ogg|json|xml|pdf|zip)(?:\\?[^\\s"\'`<>]*)?';

  function printableRatio(v) {
    if (!v) return 0;
    let p = 0;
    for (let i = 0; i < v.length; i += 1) {
      const c = v.charCodeAt(i);
      if (c >= 32 && c !== 127) p += 1;
    }
    return p / v.length;
  }

  /* HTML 实体解码（&#104; / &#x68;） */
  function htmlEntityDecode(s) {
    return String(s)
      .replace(/&#x([0-9a-fA-F]+);/g, (m, h) => String.fromCharCode(parseInt(h, 16)))
      .replace(/&#(\d+);/g, (m, d) => String.fromCharCode(parseInt(d, 10)));
  }

  /* String.fromCharCode(104,116,...) 还原 */
  function fromCharCodeDecode(text) {
    return String(text).replace(/String\.fromCharCode\s*\(\s*([0-9,\s]+?)\s*\)/g, (m, args) => {
      try {
        const codes = args.split(',').map((v) => parseInt(v.trim(), 10)).filter((n) => !Number.isNaN(n));
        if (!codes.length) return m;
        return JSON.stringify(String.fromCharCode.apply(null, codes));
      } catch (e) { return m; }
    });
  }

  /* Base32 解码 */
  function base32Decode(s) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const clean = String(s).toUpperCase().replace(/=+/g, '').replace(/\s/g, '');
    let bits = 0;
    let value = 0;
    let out = '';
    for (let i = 0; i < clean.length; i += 1) {
      const idx = alphabet.indexOf(clean[i]);
      if (idx < 0) return '';
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        out += String.fromCharCode((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return out;
  }

  /* 还原 Obfuscator.io 式字符串数组：var _0xab12 = ['a','b']; _0xab12[0x2] */
  function restoreStringArrays(text) {
    if (!text) return text;
    const dict = {};
    const declRe = /(?:var|let|const)?\s*(_0x[a-fA-F0-9]{2,})\s*=\s*\[((?:(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*,?\s*)+)\]/g;
    let m;
    while ((m = declRe.exec(text)) !== null) {
      const parts = m[2].match(/(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')/g) || [];
      if (parts.length < 2) continue;
      dict[m[1]] = parts.map((p) => p.slice(1, -1));
    }
    const names = Object.keys(dict);
    if (!names.length) return text;

    let out = text;
    names.forEach((name) => {
      const safe = name.replace(/[$]/g, '\\$');
      const useRe = new RegExp(safe + '\\s*\\[\\s*(?:0x([0-9a-fA-F]+)|(\\d+))\\s*\\]', 'g');
      out = out.replace(useRe, (whole, hex, dec) => {
        const idx = hex !== undefined ? parseInt(hex, 16) : parseInt(dec, 10);
        const val = dict[name][idx];
        return val === undefined ? whole : JSON.stringify(val);
      });
    });
    return out;
  }

  function rot13(s) {
    return s.replace(/[a-zA-Z]/g, (c) => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    });
  }

  function tryDecode(s, depth) {
    const level = depth || 0;
    const out = [];
    const seen = {};
    function push(v) {
      if (v && v !== s && !seen[v] && printableRatio(v) > 0.6) { seen[v] = 1; out.push(v); }
    }
    if (!s || s.length < 4) return out;

    if (/\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}/.test(s)) {
      try {
        push(s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
          .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))));
      } catch (e) { /* 忽略 */ }
    }

    if (s.indexOf('%') >= 0) {
      try { push(decodeURIComponent(s)); } catch (e) { /* 忽略 */ }
    }

    const t = s.trim();
    if (/^[A-Za-z0-9+/_-]{8,}={0,2}$/.test(t)) {
      try {
        let b = t.replace(/-/g, '+').replace(/_/g, '/');
        const pad = b.length % 4;
        if (pad === 2) b += '==';
        else if (pad === 3) b += '=';
        else if (pad === 1) b = '';
        if (b) push(atob(b));
      } catch (e) { /* 忽略 */ }
    }

    if (/^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0) {
      try {
        let hex = '';
        for (let i = 0; i < t.length; i += 2) hex += String.fromCharCode(parseInt(t.substr(i, 2), 16));
        push(hex);
      } catch (e) { /* 忽略 */ }
    }

    if (/[a-zA-Z]/.test(s)) {
      const r13 = rot13(s);
      if (new RegExp('^(?:' + PATH_RE_SRC + ')$', 'i').test(r13)) push(r13);
    }

    /* HTML 实体（&#104; / &#x68;） */
    if (/&#(?:x[0-9a-fA-F]+|\d+);/.test(s)) {
      try { push(htmlEntityDecode(s)); } catch (e) { /* 忽略 */ }
    }

    /* Base32 */
    if (/^[A-Z2-7]{16,}={0,6}$/.test(t)) {
      try {
        const b32 = base32Decode(t);
        if (b32) push(b32);
      } catch (e) { /* 忽略 */ }
    }

    /* 反转字符串（混淆器常用 split('').reverse().join('')） */
    if (t.length >= 8) {
      const rev = t.split('').reverse().join('');
      if (/^(https?:\/\/|\.{0,2}\/)/.test(rev)) push(rev);
    }

    /* 多层嵌套：对解出来的结果再解一层（最多 2 层） */
    if (level < 2) {
      out.slice().forEach((v) => {
        tryDecode(v, level + 1).forEach((x) => push(x));
      });
    }
    return out;
  }

  function mergeConcat(text) {
    const re = /(["'`])((?:\\.|[^"'`\\])*)\1(?:\s*\+\s*(["'`])((?:\\.|[^"'`\\])*)\3)+/g;
    return text.replace(re, (m) => {
      const parts = [];
      const sr = /(["'`])((?:\\.|[^"'`\\])*)\1/g;
      let x;
      while ((x = sr.exec(m)) !== null) parts.push(x[2]);
      return '"' + parts.join('') + '"';
    });
  }

  /* 把任意原始地址转成绝对 URL */
  function absUrl(u, base) {
    if (!u) return null;
    let value = String(u).trim().replace(/^["']|["']$/g, '');
    if (!value || /^(data|blob|javascript|mailto|tel|about|chrome-extension):/i.test(value)) return null;
    if (value.charAt(0) === '#') return null;
    try {
      const x = new URL(value, base);
      if (x.protocol !== 'http:' && x.protocol !== 'https:') return null;
      return x.href;
    } catch (e) { return null; }
  }

  /* 资源分类（后端分组键） */
  function bucketOf(url) {
    const p = (url.split('?')[0].split('#')[0] || '').toLowerCase();
    if (/\.(png|jpe?g|gif|webp|svg|bmp|ico|avif)$/.test(p)) return 'images';
    if (/\.(woff2?|ttf|otf|eot)$/.test(p)) return 'fonts';
    if (/\.css$/.test(p)) return 'styles';
    if (/\.m?js$/.test(p)) return 'scripts';
    if (/\.(mp4|webm|ogv|m4v|mov)$/.test(p)) return 'videos';
    if (/\.(mp3|wav|m4a|flac|aac|ogg)$/.test(p)) return 'audios';
    if (/\/api\b|api\.|\/v\d+\/|\.php$|\.json$|\.xml$/.test(p)) return 'links';
    return 'links';
  }

  /* ---------------------------------------------------------------- HTML 解析 */

  function makeItem(url, source) {
    return { url, filename: filenameOf(url), host: hostOf(url), source: source || 'tag' };
  }

  function collectInto(store, url, source, limit) {
    if (!url) return;
    const bucket = bucketOf(url);
    const list = store[bucket] || (store[bucket] = []);
    if (list.length >= (limit || 800)) return;
    if (list.some((it) => it.url === url)) return;
    list.push(makeItem(url, source));
  }

  function deepMine(text, base, store) {
    if (!text) return;
    /* 先还原混淆结构：字符串数组索引、fromCharCode、HTML 实体 */
    let src = restoreStringArrays(text);
    src = fromCharCodeDecode(src);
    if (/&#(?:x[0-9a-fA-F]+|\d+);/.test(src)) src = htmlEntityDecode(src);
    const merged = mergeConcat(src);
    let m;

    const re1 = /https?:\/\/[^\s"'`<>()\\]+/gi;
    while ((m = re1.exec(merged)) !== null) collectInto(store, absUrl(m[0], base), 'js.url');

    const re2 = new RegExp(PATH_RE_SRC, 'gi');
    while ((m = re2.exec(merged)) !== null) collectInto(store, absUrl(m[0], base), 'js.path');

    const re3 = /"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|`((?:\\.|[^`\\])*)`/g;
    while ((m = re3.exec(merged)) !== null) {
      const s = m[1] !== undefined ? m[1] : (m[2] !== undefined ? m[2] : m[3]);
      if (!s || s.length < 4) continue;
      if (/^(https?:\/\/|\.{0,2}\/)/i.test(s)) collectInto(store, absUrl(s, base), 'js.literal');
      const decoded = tryDecode(s);
      for (let i = 0; i < decoded.length; i += 1) {
        const d = decoded[i];
        let x;
        if (/^(https?:\/\/|\.{0,2}\/)/i.test(d)) collectInto(store, absUrl(d, base), 'js.decoded');
        const r2 = /https?:\/\/[^\s"'`<>()\\]+/gi;
        while ((x = r2.exec(d)) !== null) collectInto(store, absUrl(x[0], base), 'js.decoded');
        const r3 = new RegExp(PATH_RE_SRC, 'gi');
        while ((x = r3.exec(d)) !== null) collectInto(store, absUrl(x[0], base), 'js.decoded');
      }
    }

    const re4 = /(?:fetch|axios\.get|axios\.post|axios|XMLHttpRequest|\.ajax)\s*\(\s*["'`]([^"'`]+)["'`]/gi;
    while ((m = re4.exec(text)) !== null) collectInto(store, absUrl(m[1], base), 'js.api');
  }

  function parseHtmlResources(html, baseUrl, includeHtml) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    let base = baseUrl;
    const baseEl = doc.querySelector('base[href]');
    if (baseEl) {
      const resolved = absUrl(baseEl.getAttribute('href'), baseUrl);
      if (resolved) base = resolved;
    }

    const store = { images: [], videos: [], audios: [], links: [], scripts: [], styles: [], fonts: [], iframes: [], inline: [] };

    doc.querySelectorAll('img').forEach((el) => {
      collectInto(store, absUrl(el.getAttribute('src'), base), 'img');
      ['data-src', 'data-original', 'data-lazy-src', 'data-url'].forEach((attr) => {
        collectInto(store, absUrl(el.getAttribute(attr), base), attr);
      });
      const ss = el.getAttribute('srcset') || el.getAttribute('data-srcset');
      if (ss) ss.split(',').forEach((part) => collectInto(store, absUrl(part.trim().split(/\s+/)[0], base), 'srcset'));
    });

    doc.querySelectorAll('link[href]').forEach((el) => {
      const rel = (el.getAttribute('rel') || '').toLowerCase();
      const href = absUrl(el.getAttribute('href'), base);
      if (!href) return;
      if (rel.indexOf('stylesheet') >= 0) collectInto(store, href, 'link.css');
      else if (rel.indexOf('icon') >= 0) collectInto(store, href, 'favicon');
      else if (rel.indexOf('preload') >= 0 || rel.indexOf('modulepreload') >= 0) {
        const as = (el.getAttribute('as') || '').toLowerCase();
        if (as === 'font') collectInto(store, href, 'preload.font');
        else if (as === 'image') collectInto(store, href, 'preload.image');
        else if (as === 'script') collectInto(store, href, 'preload.script');
        else if (as === 'style') collectInto(store, href, 'preload.style');
        else collectInto(store, href, 'preload');
      } else if (rel.indexOf('manifest') >= 0) collectInto(store, href, 'manifest');
      else if (/prefetch|alternate|mask-icon|apple-touch/.test(rel)) collectInto(store, href, 'link.' + rel.split(/\s+/)[0]);
    });

    doc.querySelectorAll('script[src]').forEach((el) => collectInto(store, absUrl(el.getAttribute('src'), base), 'script'));

    /* 冷门但真实存在的资源容器：object / embed / track / 输入图像 / SVG 图像 */
    doc.querySelectorAll('object[data]').forEach((el) => collectInto(store, absUrl(el.getAttribute('data'), base), 'object'));
    doc.querySelectorAll('embed[src]').forEach((el) => collectInto(store, absUrl(el.getAttribute('src'), base), 'embed'));
    doc.querySelectorAll('track[src]').forEach((el) => collectInto(store, absUrl(el.getAttribute('src'), base), 'track'));
    doc.querySelectorAll('input[type="image"][src]').forEach((el) => collectInto(store, absUrl(el.getAttribute('src'), base), 'input.image'));
    doc.querySelectorAll('image').forEach((el) => {
      const href = el.getAttribute('href') || el.getAttribute('xlink:href');
      collectInto(store, absUrl(href, base), 'svg.image');
    });
    doc.querySelectorAll('meta[itemprop="image"], meta[property="og:image:secure_url"], meta[name="msapplication-TileImage"], meta[name="twitter:image"]').forEach((el) => {
      collectInto(store, absUrl(el.getAttribute('content'), base), 'meta.image');
    });
    /* picture 里的多分辨率候选 */
    doc.querySelectorAll('source[srcset], source[data-srcset]').forEach((el) => {
      const ss = el.getAttribute('srcset') || el.getAttribute('data-srcset');
      if (ss) ss.split(',').forEach((part) => collectInto(store, absUrl(part.trim().split(/\s+/)[0], base), 'srcset'));
    });
    /* 任意带 data-bg / data-background / data-image 的元素（懒加载背景图） */
    const bgAttrs = ['data-bg', 'data-background', 'data-background-image', 'data-image', 'data-poster'];
    doc.querySelectorAll('[' + bgAttrs.join('],[') + ']').forEach((el) => {
      bgAttrs.forEach((attr) => {
        const val = el.getAttribute(attr);
        if (!val) return;
        const m = /url\(\s*['"]?([^'")]+)/i.exec(val);
        collectInto(store, absUrl(m ? m[1] : val, base), attr);
      });
    });

    doc.querySelectorAll('video').forEach((el) => {
      collectInto(store, absUrl(el.getAttribute('src'), base), 'video');
      collectInto(store, absUrl(el.getAttribute('poster'), base), 'poster');
    });
    doc.querySelectorAll('audio').forEach((el) => collectInto(store, absUrl(el.getAttribute('src'), base), 'audio'));
    doc.querySelectorAll('source').forEach((el) => {
      const src = absUrl(el.getAttribute('src'), base);
      if (!src) return;
      if (bucketOf(src) === 'videos') collectInto(store, src, 'source.video');
      else if (bucketOf(src) === 'audios') collectInto(store, src, 'source.audio');
      else collectInto(store, src, 'source');
    });

    doc.querySelectorAll('iframe[src]').forEach((el) => collectInto(store, absUrl(el.getAttribute('src'), base), 'iframe'));
    doc.querySelectorAll('a[href]').forEach((el) => collectInto(store, absUrl(el.getAttribute('href'), base), 'a.href'));

    /* 内联样式里的 url() */
    let cssText = '';
    doc.querySelectorAll('style').forEach((el) => { cssText += el.textContent || ''; });
    doc.querySelectorAll('[style]').forEach((el) => { cssText += ' ' + (el.getAttribute('style') || ''); });
    (cssText.match(/url\(\s*['"]?([^'")]+)['"]?\s*\)/gi) || []).forEach((raw) => {
      const clean = raw.replace(/^url\(\s*['"]?/i, '').replace(/['"]?\s*\)$/, '').trim();
      collectInto(store, absUrl(clean, base), 'css.url');
    });

    /* 内联资源：单文件应用（H5、小工具、打包后的页面）的代码与素材全在 HTML 里，
       以前只认外链 <script src>，导致这类页面「只能抓到音频和链接」 */
    const pushInline = (name, content, source, mime) => {
      if (!content || !name) return;
      if (store.inline.some((x) => x.filename === name)) return;
      store.inline.push({
        url: 'inline://' + name,
        filename: name,
        host: 'inline',
        source: source,
        inline: content,
        mime: mime || '',
        size: content.length,
      });
    };

    let inlineJs = '';
    doc.querySelectorAll('script:not([src])').forEach((el, i) => {
      const code = el.textContent || '';
      inlineJs += code + '\n';
      const type = (el.getAttribute('type') || '').toLowerCase();
      if (type && !/javascript|ecmascript|module|json/.test(type)) return;
      if (code.trim().length < 160) return;
      const id = el.id ? el.id.replace(/[^\w.-]/g, '_') : 's' + (i + 1);
      pushInline('inline-' + id + (type.indexOf('json') >= 0 ? '.json' : '.js'), code, 'inline.script');
    });

    doc.querySelectorAll('style').forEach((el, i) => {
      const code = el.textContent || '';
      if (code.trim().length < 160) return;
      pushInline('inline-style-' + (i + 1) + '.css', code, 'inline.style');
    });

    /* 内联 data: URI 素材（base64 直接焊在 HTML 或 CSS 里） */
    const dataRe = /data:(image|audio|video|font)\/([a-z0-9.+-]+);base64,([A-Za-z0-9+/=]{200,})/gi;
    let dm;
    let dataCount = 0;
    const dataScanTargets = cssText + '\n' + html.slice(0, 3000000);
    while ((dm = dataRe.exec(dataScanTargets)) !== null && dataCount < 40) {
      const kind = dm[1];
      const ext = dm[2].toLowerCase().replace('svg+xml', 'svg').replace('jpeg', 'jpg').replace('x-icon', 'ico');
      dataCount += 1;
      pushInline('data-' + dataCount + '-' + kind + '.' + ext, dm[3], 'inline.data', kind + '/' + dm[2]);
    }

    if (inlineJs) deepMine(inlineJs, base, store);
    if (doc.body) deepMine(doc.body.innerHTML || '', base, store);

    /* 兜底：整页裸露 URL 扫描 */
    const rawHits = html.match(/https?:\/\/[^\s"'`<>()\\]+/gi) || [];
    rawHits.slice(0, 400).forEach((u) => {
      const clean = absUrl(u.replace(/[),.;]+$/, ''), base);
      if (clean && /\.(png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|css|m?js|mp4|webm|mp3|wav)/i.test(clean)) {
        collectInto(store, clean, 'raw.scan');
      }
    });

    const title = (doc.title || '').trim();
    const metaGet = (sel) => {
      const el = doc.querySelector(sel);
      return el ? (el.getAttribute('content') || '') : '';
    };
    /* JSON-LD 结构化数据里的资源地址 */
    doc.querySelectorAll('script[type="application/ld+json"]').forEach((el) => {
      try {
        const json = JSON.parse(el.textContent || '');
        const walk = (node) => {
          if (!node) return;
          if (typeof node === 'string') {
            if (/^(https?:\/\/|\.{0,2}\/)/.test(node)) collectInto(store, absUrl(node, base), 'json-ld');
            return;
          }
          if (Array.isArray(node)) { node.forEach(walk); return; }
          if (typeof node === 'object') Object.keys(node).forEach((k) => walk(node[k]));
        };
        walk(json);
      } catch (e) { /* 忽略 */ }
    });

    /* 内联 JSON 数据块：__NEXT_DATA__、Nuxt、importmap、speculationrules
       —— Next.js / Nuxt 站点的图片、chunk、接口地址几乎全在这里 */
    const jsonWalk = (node, source) => {
      if (node === null || node === undefined) return;
      if (typeof node === 'string') {
        if (node.length > 3 && node.length < 400 && /^(https?:\/\/|\/|\.{1,2}\/)/.test(node)) {
          collectInto(store, absUrl(node, base), source);
        }
        return;
      }
      if (Array.isArray(node)) { node.forEach((n) => jsonWalk(n, source)); return; }
      if (typeof node === 'object') Object.keys(node).forEach((k) => jsonWalk(node[k], source));
    };

    doc.querySelectorAll('script[type="application/json"], script[id="__NEXT_DATA__"], script[type="importmap"], script[type="speculationrules"]').forEach((el) => {
      const raw = (el.textContent || '').trim();
      if (!raw || raw.length > 4000000) return;
      try {
        jsonWalk(JSON.parse(raw), 'json.inline');
      } catch (e) {
        /* 不严格时退化成路径扫描 */
        (raw.match(/"(?:https?:\/\/|\/)[^"]{3,220}"/g) || []).slice(0, 600).forEach((h) => {
          collectInto(store, absUrl(h.slice(1, -1), base), 'json.inline');
        });
      }
    });

    /* og:video / twitter:player 等媒体地址 */
    ['og:video', 'og:video:url', 'og:video:secure_url', 'og:audio', 'og:audio:url',
      'twitter:player:stream'].forEach((prop) => {
      const val = metaGet('meta[property="' + prop + '"]') || metaGet('meta[name="' + prop + '"]');
      if (val) collectInto(store, absUrl(val, base), prop);
    });

    /* video/audio 懒加载 data-* 属性 */
    doc.querySelectorAll('video, audio').forEach((el) => {
      ['data-src', 'data-url', 'data-video', 'data-audio'].forEach((attr) => {
        collectInto(store, absUrl(el.getAttribute(attr), base), 'data.media');
      });
    });

    const faviconItem = doc.querySelector('link[rel*="icon"][href]');
    const favicon = faviconItem ? (absUrl(faviconItem.getAttribute('href'), base) || '') : '';
    const ogImage = metaGet('meta[property="og:image"]') || metaGet('meta[name="twitter:image"]');
    if (ogImage) {
      const resolved = absUrl(ogImage, base);
      if (resolved && !store.images.some((it) => it.url === resolved)) {
        store.images.unshift(makeItem(resolved, 'og:image'));
      }
    }

    const counts = {};
    Object.keys(store).forEach((k) => { counts[k] = store[k].length; });

    const page = {
      title: title.slice(0, 300),
      description: metaGet('meta[name="description"]').slice(0, 500),
      keywords: metaGet('meta[name="keywords"]').slice(0, 300),
      author: metaGet('meta[name="author"]'),
      ogTitle: metaGet('meta[property="og:title"]'),
      ogImage,
      canonical: absUrl((doc.querySelector('link[rel="canonical"]') || { getAttribute: () => null }).getAttribute('href'), base) || '',
      charset: (doc.characterSet || '').toLowerCase(),
      generator: metaGet('meta[name="generator"]'),
      favicon,
      lang: doc.documentElement.getAttribute('lang') || '',
    };

    const sameOriginLinks = [];
    doc.querySelectorAll('a[href]').forEach((el) => {
      const h = absUrl(el.getAttribute('href'), base);
      if (!h) return;
      try {
        const a = new URL(h);
        const b = new URL(base);
        if (a.host === b.host && !NON_HTML_EXT.test(a.pathname)) sameOriginLinks.push(h);
      } catch (e) { /* 忽略 */ }
    });

    return {
      page,
      resources: store,
      counts,
      total: Object.keys(counts).reduce((sum, k) => sum + counts[k], 0),
      sameOriginLinks: Array.from(new Set(sameOriginLinks)),
      doc,
      inlineJs,
      html: includeHtml ? html.slice(0, 1200000) : undefined,
    };
  }

  /* 二级挖掘：跟进 CSS 文件，解析其中的 url() 与 @import */
  async function enrichFromCss(store, limit) {
    const styles = (store.styles || []).slice(0, limit || 8);
    await pool(styles, async (item) => {
      try {
        const got = await fetchViaProxy(item.url, false);
        if (typeof got.data !== 'string') return;
        const body = got.data;
        (body.match(/url\(\s*['"]?([^'")]+)['"]?\s*\)/gi) || []).slice(0, 400).forEach((raw) => {
          const clean = raw.replace(/^url\(\s*['"]?/i, '').replace(/['"]?\s*\)$/, '').trim();
          collectInto(store, absUrl(clean, item.url), 'css.remote');
        });
        (body.match(/@import\s+(?:url\(?\s*)?['"][^'"]+['"]/gi) || []).forEach((raw) => {
          const m = raw.match(/['"]([^'"]+)['"]/);
          if (m) collectInto(store, absUrl(m[1], item.url), 'css.import');
        });
        deepMine(body.slice(0, 400000), item.url, store);
      } catch (e) { /* 单个 CSS 失败不影响整体 */ }
    }, 2);
  }

  /* 二级挖掘：跟进外链 JS
     现代站点的图片、接口、chunk 路径大量写死在 JS 里，这块以前是纯盲区 */
  async function enrichFromScripts(store, limit) {
    const scripts = (store.scripts || []).slice(0, limit || 12);
    await pool(scripts, async (item) => {
      try {
        const got = await fetchViaProxy(item.url, false);
        if (typeof got.data !== 'string') return;
        const body = got.data;
        if (body.length > 4000000) return;
        deepMine(body, item.url, store);
        /* 动态 import() 与 new URL('...', import.meta.url)：webpack 分片的地道写法 */
        const dyn = body.match(/(?:import\s*\(\s*|\bnew\s+URL\s*\(\s*)['"`][^'"`]+['"`]/g) || [];
        dyn.slice(0, 400).forEach((raw) => {
          const m = raw.match(/['"`]([^'"`]+)['"`]/);
          if (m && m[1].length > 3) collectInto(store, absUrl(m[1], item.url), 'js.dynamic');
        });
        /* sourceMappingURL 泄露的源码包 */
        const smu = body.match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
        if (smu) collectInto(store, absUrl(smu[1], item.url), 'js.sourcemap');
      } catch (e) { /* 单个 JS 失败不影响整体 */ }
    }, 2);
  }

  /* robots.txt：拿 Disallow 目录与 Sitemap 地址，这是隐藏路径最直接的线索 */
  async function mineRobots(baseUrl, store) {
    let origin;
    try { origin = new URL(baseUrl).origin; } catch (e) { return []; }
    try {
      const got = await fetchViaProxy(origin + '/robots.txt', false);
      const body = typeof got.data === 'string' ? got.data : '';
      if (!body || /<!doctype html|<html[\s>]/i.test(body.slice(0, 300))) return [];
      const disallow = [];
      const re = /^(?:disallow|allow)\s*:\s*(\S+)/gim;
      let m;
      while ((m = re.exec(body)) !== null) {
        const p = m[1].trim();
        if (!p || p === '/' || p === '*') continue;
        disallow.push(p.charAt(0) === '/' ? p : '/' + p);
        if (disallow.length >= 80) break;
      }
      (body.match(/^sitemap\s*:\s*(\S+)/gim) || []).slice(0, 5).forEach((line) => {
        const u = line.replace(/^sitemap\s*:\s*/i, '').trim();
        collectInto(store, absUrl(u, origin), 'robots.sitemap');
      });
      return disallow;
    } catch (e) { return []; }
  }

  async function mineSitemap(url, store, limit) {
    try {
      const got = await fetchViaProxy(url, false);
      const body = typeof got.data === 'string' ? got.data : '';
      if (!body || /<!doctype html/i.test(body.slice(0, 200))) return 0;
      const locs = body.match(/<loc>\s*([\s\S]*?)\s*<\/loc>/gi) || [];
      locs.slice(0, limit || 200).forEach((raw) => {
        const u = raw.replace(/<\/?loc>/gi, '').trim();
        collectInto(store, absUrl(u, url), 'sitemap');
      });
      return locs.length;
    } catch (e) { return 0; }
  }

  /* 暴露文件探测：直接砸门，看服务器有没有把备份、配置、源码目录放在公网 */
  const EXPOSED_TARGETS = [
    ['.env', '环境变量文件，常含数据库密码与 API Key'],
    ['.git/config', 'Git 配置，配合 .git/ 可还原整站源码'],
    ['.git/HEAD', 'Git 版本指针'],
    ['backup.zip', '站点备份压缩包'],
    ['www.zip', '整站源码包'],
    ['db.sql', '数据库导出'],
    ['dump.sql', '数据库导出'],
    ['.DS_Store', 'macOS 目录索引，泄露真实文件名'],
    ['package.json', '依赖清单，泄露技术栈与内部包名'],
    ['composer.json', 'PHP 依赖清单'],
    ['web.config', 'IIS 配置文件'],
    ['.htaccess', 'Apache 重写规则'],
    ['phpinfo.php', 'PHP 环境详情页'],
    ['admin/', '后台入口'],
    ['.svn/entries', 'SVN 元数据'],
    ['.well-known/security.txt', '安全联系信息（出现属正常项）'],
  ];

  /* 代理拿不到状态码，只能靠内容特征判断是不是真文件（而不是 404 页 / SPA 兜底） */
  function looksLikeRealFile(path, body, size) {
    if (size < 20) return false;
    const head = body.slice(0, 600);
    if (/<!doctype html|<html[\s>]/i.test(head)) return false;
    if (/^\s*<\?xml/i.test(head)) return false;
    if (path.indexOf('.env') === 0) return /^[\w.-]+\s*=/m.test(body);
    if (path.indexOf('.git') === 0) return /\[core\]|ref:\s*refs/i.test(body);
    if (/\.sql$/.test(path)) return /CREATE TABLE|INSERT INTO/i.test(body);
    if (path === 'package.json' || path === 'composer.json') {
      try { return !!JSON.parse(body); } catch (e) { return false; }
    }
    if (path === '.DS_Store') return body.indexOf('Bud1') === 0;
    return true;
  }

  async function probeExposed(baseUrl) {
    let origin;
    try { origin = new URL(baseUrl).origin; } catch (e) { return []; }
    const out = [];
    await pool(EXPOSED_TARGETS, async (pair) => {
      const path = pair[0];
      const url = origin + '/' + path;
      try {
        const got = await fetchViaProxy(url, false);
        const body = typeof got.data === 'string' ? got.data : '';
        if (looksLikeRealFile(path, body, got.size)) {
          out.push({
            path: path,
            url: url,
            desc: pair[1],
            size: got.size,
            preview: body.slice(0, 140).replace(/\s+/g, ' '),
          });
        }
      } catch (e) { /* 不存在就跳过 */ }
    }, 3);
    return out;
  }

  /* ---------------------------------------------------------------- 探测 */

  async function probe(raw) {
    const normalized = normalizeUrl(raw);
    const parsed = new URL(normalized);
    const host = parsed.hostname;
    if (!host) throw err('网址缺少主机名');

    const started = performance.now();
    const [v4, v6] = await Promise.all([
      dohQuery(host, 'A', 'alidns').catch(() => []),
      dohQuery(host, 'AAAA', 'alidns').catch(() => []),
    ]);
    const ipv4 = v4.filter((r) => r.type === 'A').map((r) => r.data);
    const ipv6 = v6.filter((r) => r.type === 'AAAA').map((r) => r.data);
    const dns = {
      resolved: ipv4.length > 0 || ipv6.length > 0,
      ips: ipv4.concat(ipv6),
      ipv4,
      ipv6,
      latency: Math.round(performance.now() - started),
    };
    if (!dns.resolved) {
      dns.error = '域名解析失败（DoH 未返回 A/AAAA 记录）';
    }

    const path = (parsed.pathname || '/') + (parsed.search || '');
    const httpUrl = 'http://' + host + path;
    const httpsUrl = 'https://' + host + path;

    const [httpReach, httpsReach, pageFetch] = await Promise.all([
      reachable(httpUrl),
      reachable(httpsUrl),
      fetchViaProxy(httpsUrl, false).catch(() => null),
    ]);

    const redirectChain = [];
    let pageData = null;
    if (pageFetch) {
      try {
        pageData = parseHtmlResources(pageFetch.data, httpsUrl, false);
      } catch (e) { pageData = null; }
    }

    const mkEndpoint = (reach, url) => {
      if (!reach.open) return { open: false, url, finalUrl: url, redirectChain: [], error: reach.error };
      return {
        open: true,
        url,
        finalUrl: url,
        status: 0,
        latency: reach.ms,
        size: pageFetch && pageData ? pageFetch.size : 0,
        contentType: pageData ? 'text/html' : '',
        server: '',
        redirectChain,
        isHtml: !!pageData,
      };
    };

    const httpsResult = mkEndpoint(httpsReach, httpsUrl);
    const httpResult = mkEndpoint(httpReach, httpUrl);

    /* 纯前端拿不到响应头，安全头如实标记为不可用 */
    const security = {
      unavailable: true,
      items: SECURITY_HEADERS.map(([key, label, level]) => ({
        key, label, level, present: false, value: '',
      })),
      passed: 0,
      total: SECURITY_HEADERS.length,
      note: '浏览器无法读取跨域响应头，此项需后端服务',
    };

    const tls = {
      available: false,
      error: '浏览器不暴露 TLS 证书信息，此项需后端服务',
    };

    let score = 0;
    const hints = [];
    if (dns.resolved) score += 20;
    else hints.push('域名无法解析，站点可能不存在或 DNS 配置有误。');
    if (httpsReach.open) score += 25;
    else hints.push('HTTPS 访问失败，站点可能只支持 HTTP，存在安全风险。');
    if (httpReach.open) score += 5;
    if (httpsReach.open && httpReach.open && !redirectChain.length) {
      hints.push('HTTP 可以直接访问且未强制跳转 HTTPS，建议 301 重定向到 HTTPS。');
    }
    hints.push('纯前端模式无法检测 TLS 证书与安全响应头，评分上限受限（满分 50）。');
    if (!pageFetch) hints.push('未能通过代理取得页面正文，站点可能拒绝代理访问。');

    const grade = score >= 90 ? '优秀' : score >= 75 ? '良好' : score >= 60 ? '一般' : '待改进';

    return {
      target: host,
      input: raw,
      normalized,
      timestamp: nowIso(),
      mode: 'local',
      dns,
      http: httpResult,
      https: httpsResult,
      tls,
      security,
      summary: {
        reachable: httpReach.open || httpsReach.open,
        httpSupported: httpReach.open,
        httpsSupported: httpsReach.open,
        isHtmlSite: !!pageData,
        preferredProtocol: httpsReach.open ? 'https' : (httpReach.open ? 'http' : '-'),
        score: Math.max(0, Math.min(100, score)),
        grade,
        server: '',
        finalUrl: httpsReach.open ? httpsUrl : httpUrl,
      },
      hints,
      page: pageData ? pageData.page : null,
    };
  }

  async function probeBatch(urls) {
    const list = (urls || []).slice(0, 20);
    const results = [];
    for (const u of list) {
      try {
        results.push(await probe(u));
      } catch (e) {
        results.push({ input: u, target: u, error: e.message || '探测失败' });
      }
      await sleep(200);
    }
    return { results };
  }

  /* ---------------------------------------------------------------- 资源提取 */

  async function extract(raw, includeHtml) {
    const normalized = normalizeUrl(raw);
    const started = performance.now();
    let fetched;
    try {
      fetched = await fetchViaProxy(normalized, false);
    } catch (e) {
      throw err('请求失败：' + (e.message || '目标站点无响应'));
    }
    const parsedRes = parseHtmlResources(fetched.data, normalized, includeHtml !== false);
    const store = parsedRes.resources;
    /* 二级挖掘全部并发，但给整体设 18 秒预算：挖不完就用已有结果，不能让用户干等 */
    const origin = new URL(normalized).origin;
    const enrichJob = Promise.all([
      mineRobots(normalized, store),
      enrichFromCss(store, 5).then(() => enrichFromScripts(store, 6)),
      mineSitemap(origin + '/sitemap.xml', store, 200),
      probeExposed(normalized),
    ]).catch(() => null);
    let disallow = [];
    let exposed = [];
    const outcomes = await Promise.race([
      enrichJob,
      sleep(18000).then(() => null),
    ]);
    if (outcomes) {
      disallow = outcomes[0];
      exposed = outcomes[3];
    }
    Object.keys(store).forEach((k) => { parsedRes.counts[k] = store[k].length; });
    parsedRes.total = Object.keys(parsedRes.counts).reduce((sum, k) => sum + parsedRes.counts[k], 0);

    const page = Object.assign({
      input: raw,
      url: normalized,
      status: 0,
      contentType: 'text/html; charset=utf-8',
      size: fetched.size,
      latency: fetched.ms,
      redirected: false,
      redirectChain: [],
      server: '',
    }, parsedRes.page);

    const result = {
      page,
      resources: parsedRes.resources,
      counts: parsedRes.counts,
      total: parsedRes.total,
      exposed: exposed || [],
      robotsDisallow: disallow || [],
      mode: 'local',
    };
    if (includeHtml !== false) {
      result.html = parsedRes.html;
      result.htmlTruncated = fetched.size > 1200000;
    }
    if (!parsedRes.total) {
      result.warning = '未发现资源。目标可能拒绝代理访问，或页面内容由脚本动态生成。';
    }
    return result;
  }

  async function deepExtract(raw, depth, maxPages) {
    const normalized = normalizeUrl(raw);
    const limitDepth = Math.max(1, Math.min(Number(depth) || 2, 4));
    const limitPages = Math.max(1, Math.min(Number(maxPages) || 25, 40));
    const rootHost = hostOf(normalized);

    const queue = [{ url: normalized, level: 1 }];
    const visited = new Set([normalized]);
    const pages = [];
    const all = { images: [], videos: [], audios: [], links: [], scripts: [], styles: [], fonts: [], iframes: [], inline: [] };
    const seenAll = new Set();

    while (queue.length && pages.length < limitPages) {
      const job = queue.shift();
      let fetched;
      try {
        fetched = await fetchViaProxy(job.url, false);
      } catch (e) {
        pages.push({ url: job.url, level: job.level, title: '', status: 0, error: e.message || '抓取失败', counts: {} });
        continue;
      }
      let parsedRes;
      try {
        parsedRes = parseHtmlResources(fetched.data, job.url, false);
      } catch (e) {
        pages.push({ url: job.url, level: job.level, title: '', status: 0, error: '解析失败', counts: {} });
        continue;
      }

      Object.keys(all).forEach((bucket) => {
        (parsedRes.resources[bucket] || []).forEach((item) => {
          if (seenAll.has(item.url)) return;
          seenAll.add(item.url);
          all[bucket].push(Object.assign({}, item, { page: job.url, category: bucket }));
        });
      });

      pages.push({
        url: job.url,
        level: job.level,
        title: parsedRes.page.title,
        status: 0,
        size: fetched.size,
        counts: parsedRes.counts,
      });

      if (job.level < limitDepth) {
        parsedRes.sameOriginLinks.forEach((link) => {
          if (visited.has(link)) return;
          if (hostOf(link) !== rootHost) return;
          visited.add(link);
          queue.push({ url: link, level: job.level + 1 });
        });
      }
      await sleep(150);
    }

    /* 深挖完再统一跟进一次外链 JS，把每页里引用的隐藏路径挖出来 */
    await enrichFromScripts(all, 15);

    const counts = {};
    Object.keys(all).forEach((k) => { counts[k] = all[k].length; });
    return {
      page: {
        input: raw,
        url: normalized,
        title: pages.length ? pages[0].title : '',
        status: 0,
      },
      pages,
      pageCount: pages.length,
      resources: all,
      counts,
      total: Object.keys(counts).reduce((sum, k) => sum + counts[k], 0),
      html: '',
      mode: 'local',
    };
  }

  /* ---------------------------------------------------------------- 打包（纯前端 ZIP） */

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  }

  function crc32(bytes) {
    let table = crc32.table;
    if (!table) {
      table = crc32.table = new Uint32Array(256);
      for (let i = 0; i < 256; i += 1) {
        let c = i;
        for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        table[i] = c >>> 0;
      }
    }
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i += 1) crc = table[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
  }

  function dosTime(d) {
    return ((d.getHours() << 11) | (d.getMinutes() << 5) | (Math.floor(d.getSeconds() / 2)))
      + '\u0000';
  }

  function buildZip(files) {
    const chunks = [];
    const central = [];
    let offset = 0;

    files.forEach((file) => {
      const nameBytes = new TextEncoder().encode(file.name);
      const dataBytes = typeof file.data === 'string' ? new TextEncoder().encode(file.data) : new Uint8Array(file.data);
      const crc = crc32(dataBytes);
      const d = new Date();
      const time = ((d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2)) & 0xffff;
      const date = ((d.getFullYear() - 1980) << 9 | (d.getMonth() + 1) << 5 | d.getDate()) & 0xffff;

      const local = new Uint8Array(30 + nameBytes.length);
      const dv = new DataView(local.buffer);
      dv.setUint32(0, 0x04034b50, true);
      dv.setUint16(4, 20, true);
      dv.setUint16(6, 0, true);
      dv.setUint16(8, 0, true);
      dv.setUint16(10, time, true);
      dv.setUint16(12, date, true);
      dv.setUint32(14, crc, true);
      dv.setUint32(18, dataBytes.length, true);
      dv.setUint32(22, dataBytes.length, true);
      dv.setUint16(26, nameBytes.length, true);
      dv.setUint16(28, 0, true);
      local.set(nameBytes, 30);

      chunks.push(local, dataBytes);

      const cen = new Uint8Array(46 + nameBytes.length);
      const cv = new DataView(cen.buffer);
      cv.setUint32(0, 0x02014b50, true);
      cv.setUint16(4, 20, true);
      cv.setUint16(6, 20, true);
      cv.setUint16(8, 0, true);
      cv.setUint16(10, 0, true);
      cv.setUint16(12, time, true);
      cv.setUint16(14, date, true);
      cv.setUint32(16, crc, true);
      cv.setUint32(20, dataBytes.length, true);
      cv.setUint32(24, dataBytes.length, true);
      cv.setUint16(28, nameBytes.length, true);
      cv.setUint16(30, 0, true);
      cv.setUint16(32, 0, true);
      cv.setUint16(34, 0, true);
      cv.setUint16(36, 0, true);
      cv.setUint32(38, 0, true);
      cv.setUint32(42, offset, true);
      cen.set(nameBytes, 46);
      central.push(cen);

      offset += local.length + dataBytes.length;
    });

    const centralSize = central.reduce((sum, c) => sum + c.length, 0);
    const end = new Uint8Array(22);
    const ev = new DataView(end.buffer);
    ev.setUint32(0, 0x06054b50, true);
    ev.setUint16(8, files.length, true);
    ev.setUint16(10, files.length, true);
    ev.setUint32(12, centralSize, true);
    ev.setUint32(16, offset, true);

    return new Blob([].concat(chunks, central, [end]), { type: 'application/zip' });
  }

  async function packZip(items, title) {
    const list = (items || []).slice(0, 60);
    const files = [];
    const index = [];

    index.push('URL\t分类\t文件名\t状态');

    for (const item of list) {
      const name = item.filename || filenameOf(item.url) || 'file';
      const folder = (item.category || 'links') + '/';
      const entryName = folder + name;
      /* 内联资源不需要再请求，直接把内容写进包 */
      if (item.inline) {
        const data = item.mime ? base64ToBytes(item.inline) : item.inline;
        files.push({ name: entryName, data: data });
        index.push(item.url + '\t' + (item.category || '') + '\t' + entryName + '\t成功（内联）');
        continue;
      }
      try {
        const got = await fetchViaProxy(item.url, true);
        files.push({ name: entryName, data: got.data });
        index.push(item.url + '\t' + (item.category || '') + '\t' + entryName + '\t成功');
      } catch (e) {
        index.push(item.url + '\t' + (item.category || '') + '\t-\t失败：' + (e.message || '代理拒绝'));
      }
      await sleep(60);
    }

    files.unshift({
      name: '资源清单.txt',
      data: 'M87 资源清单\n页面：' + (title || '') + '\n导出时间：' + new Date().toLocaleString() + '\n\n'
        + index.join('\n') + '\n',
    });

    return buildZip(files);
  }

  /* ---------------------------------------------------------------- 路由分发 */

  function parseQuery(path) {
    const q = path.indexOf('?');
    const search = q >= 0 ? path.slice(q) : '';
    const params = new URLSearchParams(search);
    const out = {};
    params.forEach((v, k) => { out[k] = v; });
    return out;
  }

  async function localApi(path, options) {
    const opts = options || {};
    const clean = path.split('?')[0];
    const query = parseQuery(path);
    const body = opts.body && typeof opts.body === 'object' ? opts.body : {};
    const payload = Object.assign({}, query, body);

    if (clean === '/api/status') {
      return { ok: true, mode: 'local', sessions: 0, packets: 0, uptime: 0 };
    }
    if (clean === '/api/tools/probe') return probe(payload.url);
    if (clean === '/api/tools/probe-batch') return probeBatch(body.urls || []);
    if (clean === '/api/tools/extract') return extract(payload.url, payload.html !== 'false');
    if (clean === '/api/tools/deep-extract') {
      return deepExtract(payload.url, payload.depth, payload.max_pages);
    }
    if (clean === '/api/tools/dns') return dnsLookup(payload.url, payload.type, payload.resolver);

    throw err('该功能需要后端服务（纯前端模式不支持抓包/会话类接口）');
  }

  NS.localMode = /\.github\.io$/.test(location.hostname)
    || location.search.indexOf('local=1') >= 0
    || location.protocol === 'file:';

  NS.local = {
    probe,
    probeBatch,
    extract,
    deepExtract,
    dnsLookup,
    packZip,
    buildZip,
    fetchViaProxy,
    localApi,
  };
})();
