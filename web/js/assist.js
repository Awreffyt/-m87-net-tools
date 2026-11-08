/* © 2026 M87 · v2.9.26 辅助增强模块
 * 功能：门禁站提交云端破解后，自动轮询快照，破解完成自动出结果。
 * 原版行为：提交队列后提示「请过几分钟重新点一次抓取」，需要用户手动重试。
 * 本模块：自动跟进，每 45 秒查一次快照，最多 20 次（约 15 分钟），
 *        命中后自动触发原「开始提取」按钮，复用全部现有解析与展示逻辑。
 * 不改动任何现有 UI 与业务代码，只监听网络与定时点击。
 */
(function () {
  'use strict';
  if (window.__M87_ASSIST__) return;
  window.__M87_ASSIST__ = true;

  var MAX_TRIES = 20;
  var GAP_MS = 45000;
  var pollTimer = null;
  var pollCount = 0;
  var missUrl = null;      // 最近一次 404 的快照地址（第一个，最接近规范形式）
  var titleBase = null;

  function noteMiss(u) {
    if (!missUrl && u && u.indexOf('/snapshots/') > -1) missUrl = u;
  }

  /* ---- 网络监听：抓 404 快照 + 云端上报动作 ---- */
  var _fetch = window.fetch;
  if (_fetch) {
    window.fetch = function (u) {
      var p = _fetch.apply(this, arguments);
      try {
        var su = typeof u === 'string' ? u : (u && u.url) || '';
        if (su.indexOf('/snapshots/') > -1) {
          p.then(function (r) { if (r.status === 404) noteMiss(su); }).catch(function () {});
        } else if (su.indexOf('ptsv2.com') > -1) {
          arm();
        }
      } catch (e) {}
      return p;
    };
  }
  var _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m, u) {
    try {
      var su = String(u || '');
      if (su.indexOf('/snapshots/') > -1) {
        this.addEventListener('load', function () {
          if (this.status === 404) noteMiss(su);
        });
      } else if (su.indexOf('ptsv2.com') > -1) {
        arm();
      }
    } catch (e) {}
    return _open.apply(this, arguments);
  };
  if (navigator.sendBeacon) {
    var _beacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (u) {
      try { if (String(u || '').indexOf('ptsv2.com') > -1) arm(); } catch (e) {}
      return _beacon.apply(navigator, arguments);
    };
  }

  /* ---- 轮询 ---- */
  function arm() {
    if (pollTimer) return;               // 已在跟进中
    var inp = document.getElementById('extractInput');
    if (!inp || !inp.value) return;
    var btn = document.getElementById('extractBtn');
    if (!btn) return;
    pollCount = 0;
    titleBase = document.title;
    pollTimer = setInterval(tick, GAP_MS);
    tick();
  }

  function tick() {
    pollCount++;
    var done = pollCount >= MAX_TRIES;
    var hit = false;
    if (missUrl) {
      /* 同步检查快照是否已生成 */
      var x = new XMLHttpRequest();
      x.open('GET', missUrl + (missUrl.indexOf('?') > -1 ? '&' : '?') + 't=' + Date.now(), false);
      try { x.send(); hit = (x.status === 200 && (x.responseText || '').length > 500); } catch (e) {}
    }
    if (hit) {
      stop();
      var btn = document.getElementById('extractBtn');
      if (btn && !btn.disabled) btn.click();   // 复用原提取逻辑，快照命中，秒出
    } else if (done) {
      stop();
    } else if (titleBase !== null) {
      document.title = titleBase + ' · 云端破解中(' + pollCount + '/' + MAX_TRIES + ')';
    }
  }

  function stop() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    if (titleBase !== null) { document.title = titleBase; titleBase = null; }
    missUrl = null;
  }
})();
