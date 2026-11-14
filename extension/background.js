/* M87 端点直连 —— 后台
   收到请求就在后台开一个标签页，让浏览器自己把页面跑完（门禁、Cookie、JS 渲染全都走浏览器本来的流程），
   内容稳定后把最终 DOM 交回去，然后关掉标签页。
   不解析、不改写、不落盘、不外发。 */

const MAX_WAIT = 45000;   // 单个页面最多等 45 秒
const POLL = 600;
const SETTLE = 2;         // 连续两次内容一致才算稳定

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function waitLoaded(tabId) {
  return new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      chrome.tabs.onUpdated.removeListener(onUpd);
      resolve(true);
    };
    function onUpd(id, info) {
      if (id === tabId && info.status === 'complete') finish();
    }
    chrome.tabs.onUpdated.addListener(onUpd);
    chrome.tabs.get(tabId).then(t => { if (t && t.status === 'complete') finish(); }).catch(finish);
    setTimeout(finish, 20000);
  });
}

async function readHtml(tabId) {
  try {
    const [r] = await chrome.scripting.executeScript({
      target: { tabId, allFrames: false },
      func: () => ({
        h: document.documentElement ? document.documentElement.outerHTML : '',
        u: location.href,
        t: document.title || '',
        r: document.readyState,
      }),
    });
    return (r && r.result) || { h: '', u: '', t: '', r: '' };
  } catch (e) {
    return { h: '', u: '', t: '', r: 'error', err: String(e && e.message || e) };
  }
}

function looksChallenge(s) {
  const head = (s || '').slice(0, 8000);
  return (head.indexOf('slowAES') >= 0 || head.indexOf('toNumbers(') >= 0) && head.indexOf('document.cookie') >= 0;
}

async function grab(url) {
  let tab = null;
  const t0 = Date.now();
  try {
    tab = await chrome.tabs.create({ url, active: false });
    await waitLoaded(tab.id);

    let prev = '';
    let same = 0;
    let best = null;

    while (Date.now() - t0 < MAX_WAIT) {
      await sleep(POLL);
      const snap = await readHtml(tab.id);
      if (!snap || !snap.h) continue;
      best = snap;

      if (snap.h === prev) same += 1; else same = 0;
      prev = snap.h;

      /* 页面已稳定、且不是那道挑战页 —— 收工 */
      if (same >= SETTLE && snap.r === 'complete' && !looksChallenge(snap.h)) break;
      /* 稳定但仍是挑战页：说明这站的门禁不是靠 JS 自动过的，交回去让人处理 */
      if (same >= SETTLE + 2 && looksChallenge(snap.h)) break;
    }

    if (!best || !best.h) {
      return { ok: false, error: '页面没有返回内容（可能被浏览器拦截或长时间无响应）' };
    }
    return { ok: true, html: best.h, u: best.u || url, title: best.t };
  } catch (e) {
    return { ok: false, error: String(e && e.message || e) };
  } finally {
    if (tab && tab.id != null) {
      try { await chrome.tabs.remove(tab.id); } catch (e) { /* 已经关了 */ }
    }
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.t !== 'grab' || typeof msg.url !== 'string') return;
  grab(msg.url).then(sendResponse, (e) => sendResponse({ ok: false, error: String(e && e.message || e) }));
  return true;   // 异步回复
});

/* ---- M87 页面注入 ----
   Chrome 新版本默认把新扩展的站点访问设为「点击时」，content_scripts 不会自动跑。
   这里在页面加载完成时主动注入桥，绕开那个默认值。 */
const M87_PAGE = /^https?:\/\/(awreffyt\.github\.io|localhost|127\.0\.0\.1)(:\d+)?\//i;

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status !== 'complete') return;
  const u = (tab && tab.url) || '';
  if (!M87_PAGE.test(u)) return;
  chrome.scripting.executeScript({ target: { tabId }, files: ['bridge.js'] }).catch(() => {});
});
