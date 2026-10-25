/* NetScope 前端公共工具 */
(function () {
  'use strict';

  const NS = (window.NS = window.NS || {});

  NS.$ = (sel, root = document) => root.querySelector(sel);
  NS.$$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.name = 'ApiError';
      this.status = status || 0;
    }
  }
  NS.ApiError = ApiError;

  NS.api = async function (path, options = {}) {
    const opts = Object.assign({ method: 'GET' }, options);
    const headers = Object.assign({}, opts.headers || {});
    if (opts.body !== undefined && opts.body !== null && typeof opts.body !== 'string') {
      headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    opts.headers = headers;
    let resp;
    try {
      resp = await fetch(path, opts);
    } catch (err) {
      throw new ApiError('无法连接后端服务', 0);
    }
    const raw = await resp.text();
    let data = null;
    if (raw) {
      try {
        data = JSON.parse(raw);
      } catch (err) {
        data = null;
      }
    }
    if (!resp.ok) {
      const detail = data && (data.detail || data.message);
      const message = typeof detail === 'string' ? detail
        : Array.isArray(detail) ? detail.map((d) => d.msg || d).join('；')
        : `请求失败（HTTP ${resp.status}）`;
      throw new ApiError(message, resp.status);
    }
    return data;
  };

  NS.qs = (obj) => Object.entries(obj)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');

  NS.esc = (value) => String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

  NS.fmtBytes = function (bytes) {
    const n = Number(bytes) || 0;
    if (n < 1024) return `${n} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let value = n / 1024;
    let index = 0;
    while (value >= 1024 && index < units.length - 1) {
      value /= 1024;
      index += 1;
    }
    return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[index]}`;
  };

  NS.fmtNum = (n) => (Number(n) || 0).toLocaleString('en-US');

  NS.fmtDuration = function (seconds) {
    const s = Number(seconds) || 0;
    if (s < 1) return `${Math.round(s * 1000)} ms`;
    if (s < 60) return `${s.toFixed(1)} s`;
    const m = Math.floor(s / 60);
    const rest = Math.round(s % 60);
    if (m < 60) return `${m}m ${rest}s`;
    return `${Math.floor(m / 60)}h ${m % 60}m`;
  };

  NS.clock = function (ts) {
    if (!ts) return '-';
    const d = new Date(ts * 1000);
    if (Number.isNaN(d.getTime())) return '-';
    const pad = (v, w = 2) => String(v).padStart(w, '0');
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
  };

  NS.dateTime = function (ts) {
    const d = new Date((ts || Date.now() / 1000) * 1000);
    if (Number.isNaN(d.getTime())) return '-';
    const pad = (v) => String(v).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };

  NS.debounce = function (fn, wait) {
    let timer = null;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), wait);
    };
  };

  NS.toast = function (message, isError) {
    const box = document.getElementById('toast');
    const msg = document.getElementById('toastMsg');
    if (!box || !msg) return;
    msg.textContent = message;
    box.classList.toggle('err', !!isError);
    box.classList.add('show');
    clearTimeout(NS.toast._timer);
    NS.toast._timer = setTimeout(() => box.classList.remove('show'), 2600);
  };

  NS.copyText = async function (text) {
    const value = String(text == null ? '' : text);
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
        return true;
      }
    } catch (err) {
      /* 落到下面的兜底方案 */
    }
    const area = document.createElement('textarea');
    area.value = value;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch (err) {
      ok = false;
    }
    document.body.removeChild(area);
    return ok;
  };

  NS.downloadBlob = function (blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename || 'download';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  };

  NS.downloadText = function (text, filename, mime) {
    NS.downloadBlob(new Blob([text], { type: mime || 'text/plain;charset=utf-8' }), filename);
  };

  NS.csv = function (rows) {
    return rows.map((row) => row.map((cell) => {
      const value = String(cell == null ? '' : cell);
      return /[",\n\r]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
    }).join(',')).join('\r\n');
  };

  NS.setLoading = function (button, loading, text) {
    if (!button) return;
    if (loading) {
      button.dataset.label = button.textContent;
      button.disabled = true;
      button.textContent = text || '处理中';
    } else {
      button.disabled = false;
      button.textContent = button.dataset.label || button.textContent;
    }
  };

  NS.PROTO_COLORS = {
    tcp: '#7dd3fc',
    udp: '#c4b5fd',
    dns: '#f9a8d4',
    http: '#6ee7b7',
    tls: '#fcd34d',
    icmp: '#fb923c',
    arp: '#67e8f9',
    ipv6: '#93c5fd',
    ip: '#7dd3fc',
    mqtt: '#a7f3d0',
    redis: '#fca5a5',
    memcached: '#fdba74',
    telnet: '#bef264',
    mysql: '#f0abfc',
    postgres: '#93c5fd',
    ldap: '#fde68a',
    smb: '#a5b4fc',
    modbus: '#5eead4',
    dhcp: '#fcd34d',
    ntp: '#c4b5fd',
    tftp: '#fda4af',
    stun: '#7dd3fc',
    snmp: '#86efac',
    syslog: '#d8b4fe',
    sip: '#67e8f9',
    quic: '#6ee7b7',
    wireguard: '#fda4af',
    rtp: '#fdba74',
    other: '#94a3b8',
    error: '#f87171',
  };

  NS.protoColor = (color, proto) => NS.PROTO_COLORS[color] || NS.PROTO_COLORS[String(proto || '').toLowerCase()] || '#94a3b8';
})();
