/* M87 端点直连 —— 页面侧桥
   注入在 M87 页面里，只做一件事：把页面的请求转给后台，把后台的结果送回页面。
   不读 Cookie、不上传任何东西，只在被调用时开一个后台标签页去取目标页。 */
(function () {
  'use strict';

  var MARK = '__m87_bridge_v1__';
  if (window[MARK]) return;
  window[MARK] = true;

  function reply(payload) {
    payload.t = 'm87-ext-result';
    window.postMessage(payload, '*');
  }

  window.addEventListener('message', function (ev) {
    if (ev.source !== window) return;
    var d = ev.data;
    if (!d || d.t !== 'm87-ext-grab') return;
    if (typeof d.url !== 'string' || !/^https?:/i.test(d.url)) return;

    var id = d.id || ('g' + Date.now() + Math.random().toString(36).slice(2, 7));
    try {
      chrome.runtime.sendMessage({ t: 'grab', url: d.url, id: id }, function (res) {
        if (chrome.runtime.lastError || !res) {
          reply({ id: id, ok: false, error: (chrome.runtime.lastError && chrome.runtime.lastError.message) || '扩展后台无响应' });
          return;
        }
        reply({ id: id, ok: !!res.ok, html: res.html, u: res.u, error: res.error });
      });
    } catch (e) {
      reply({ id: id, ok: false, error: '扩展调用失败：' + (e && e.message ? e.message : e) });
    }
  });

  function announce() {
    try { document.documentElement.setAttribute('data-m87-ext', '1'); } catch (e) { /* 忽略 */ }
    window.postMessage({ t: 'm87-ext-ready', v: 1 }, '*');
  }

  /* 页面脚本可能比注入晚，所以既主动喊一声，也应答页面的探询 */
  window.addEventListener('message', function (ev) {
    if (ev.source !== window) return;
    if (ev.data && ev.data.t === 'm87-ext-ping') announce();
  });

  announce();
})();
