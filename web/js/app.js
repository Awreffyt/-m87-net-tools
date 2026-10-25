/* 应用外壳：页签切换、健康检查、模块初始化 */
(function () {
  'use strict';

  const NS = window.NS;
  const $ = NS.$;

  function moveInk(tab) {
    const ink = $('#tabInk');
    if (!ink || !tab) return;
    ink.style.left = `${tab.offsetLeft}px`;
    ink.style.width = `${tab.offsetWidth}px`;
  }

  function activate(name, updateHash) {
    const tabs = NS.$$('#mainTabs .tab');
    const tab = tabs.find((item) => item.dataset.view === name);
    if (!tab) return;
    tabs.forEach((item) => item.classList.toggle('active', item === tab));
    NS.$$('.view').forEach((view) => view.classList.toggle('active', view.id === `view-${name}`));
    moveInk(tab);
    if (updateHash !== false) {
      history.replaceState(null, '', `#${name}`);
    }
    if (NS.capture && typeof NS.capture.setVisible === 'function') {
      NS.capture.setVisible(name === 'capture');
      if (name === 'capture') {
        setTimeout(() => NS.capture.refresh(), 80);
      }
    }
    window.dispatchEvent(new Event('resize'));
  }

  async function ping() {
    const pill = $('#serverPill');
    const text = $('#serverPillText');
    if (!pill || !text) return;
    try {
      const data = await NS.api('/api/status');
      pill.classList.remove('err', 'warn');
      pill.classList.add('ok');
      text.textContent = `服务正常，${data.sessions} 个会话，${NS.fmtNum(data.packets)} 个数据包`;
    } catch (err) {
      pill.classList.remove('ok', 'warn');
      pill.classList.add('err');
      text.textContent = '后端未连接';
    }
  }

  function initModules() {
    [['probe', 'probe'], ['extract', 'extract'], ['dns', 'dns'], ['capture', 'capture']].forEach(([key]) => {
      if (NS[key] && typeof NS[key].init === 'function') {
        try {
          NS[key].init();
        } catch (err) {
          console.error(`[${key}] 初始化失败`, err);
        }
      }
    });
  }

  function init() {
    const tabs = $('#mainTabs');
    if (tabs) {
      tabs.addEventListener('click', (event) => {
        const tab = event.target.closest('.tab');
        if (tab) activate(tab.dataset.view);
      });
    }

    window.addEventListener('resize', NS.debounce(() => {
      const active = $('#mainTabs .tab.active');
      if (active) moveInk(active);
    }, 120));

    initModules();

    const hash = (location.hash || '').replace('#', '');
    activate(['probe', 'extract', 'dns', 'capture'].includes(hash) ? hash : 'probe', false);
    requestAnimationFrame(() => {
      const active = $('#mainTabs .tab.active');
      if (active) moveInk(active);
    });

    ping();
    setInterval(ping, 10000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
