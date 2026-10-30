/* 资源提取 */
(function () {
  'use strict';

  const NS = window.NS;
  const $ = NS.$;
  const esc = NS.esc;

  const CATS = [
    { key: 'images', label: '图片', tag: 'IMG' },
    { key: 'videos', label: '视频', tag: 'VID' },
    { key: 'audios', label: '音频', tag: 'AUD' },
    { key: 'links', label: '链接', tag: 'A' },
    { key: 'scripts', label: '脚本', tag: 'JS' },
    { key: 'styles', label: '样式', tag: 'CSS' },
    { key: 'fonts', label: '字体', tag: 'FONT' },
    { key: 'iframes', label: '内嵌框架', tag: 'FRAME' },
  ];

  const el = {};
  const state = {
    data: null,
    cat: 'all',
    search: '',
    selected: new Set(),
    tab: 'resources',
    previewReady: false,
    mode: 'extract',
  };
  let running = false;

  function grab() {
    el.input = $('#extractInput');
    el.btn = $('#extractBtn');
    el.clear = $('#extractClear');
    el.examples = $('#extractExamples');
    el.error = $('#extractError');
    el.empty = $('#extractEmpty');
    el.loading = $('#extractLoading');
    el.result = $('#extractResult');
    el.favicon = $('#pageFavicon');
    el.title = $('#pageTitle');
    el.url = $('#pageUrl');
    el.desc = $('#pageDesc');
    el.meta = $('#pageMeta');
    el.open = $('#pageOpen');
    el.report = $('#pageReport');
    el.tabs = $('#extractTabs');
    el.resTotal = $('#resTotal');
    el.chips = $('#resChips');
    el.search = $('#resSearch');
    el.selectedMeta = $('#resSelectedMeta');
    el.selectAll = $('#resSelectAll');
    el.copy = $('#resCopy');
    el.csv = $('#resCsv');
    el.json = $('#resJson');
    el.zip = $('#resZip');
    el.list = $('#resourceList');
    el.sourceCopy = $('#sourceCopy');
    el.sourceDownload = $('#sourceDownload');
    el.sourceMeta = $('#sourceMeta');
    el.sourceCode = $('#sourceCode');
    el.previewFrame = $('#previewFrame');
    el.deepBtn = $('#deepBtn');
    el.deepDepth = $('#deepDepth');
    el.deepPages = $('#deepPages');
    el.deepPageCount = $('#deepPageCount');
    el.deepPagesList = $('#deepPagesList');
    el.expTotal = $('#expTotal');
    el.exposedMeta = $('#exposedMeta');
    el.exposedList = $('#exposedList');
    el.exposedCopy = $('#exposedCopy');
    el.robotsBlock = $('#robotsBlock');
    el.robotsList = $('#robotsList');
  }

  function setError(message) {
    if (!message) {
      el.error.classList.add('hidden');
      el.error.textContent = '';
      return;
    }
    el.error.textContent = message;
    el.error.classList.remove('hidden');
  }

  function show(name) {
    el.empty.classList.toggle('hidden', name !== 'empty');
    el.loading.classList.toggle('hidden', name !== 'loading');
    el.result.classList.toggle('hidden', name !== 'result');
  }

  function flatten() {
    if (!state.data) return [];
    const out = [];
    CATS.forEach((cat) => {
      (state.data.resources[cat.key] || []).forEach((item) => {
        out.push(Object.assign({ category: cat.key }, item));
      });
    });
    return out;
  }

  function filtered() {
    const keyword = state.search.trim().toLowerCase();
    return flatten().filter((item) => {
      if (state.cat !== 'all' && item.category !== state.cat) return false;
      if (!keyword) return true;
      return `${item.url} ${item.filename} ${item.host}`.toLowerCase().includes(keyword);
    });
  }

  function renderPage() {
    const page = state.data.page || {};
    el.title.textContent = page.title || '(无标题)';
    el.url.textContent = page.url || '';
    el.desc.textContent = page.description || '';

    if (el.favicon) {
      if (page.favicon) {
        el.favicon.innerHTML = `<img src="${esc(page.favicon)}" alt="" />`;
      }
    }

    const meta = [];
    if (page.status) meta.push(`<span class="badge blue">HTTP ${page.status}</span>`);
    if (page.size) meta.push(`<span class="badge">${NS.fmtBytes(page.size)}</span>`);
    if (page.latency) meta.push(`<span class="badge">${page.latency} ms</span>`);
    if (page.redirected) meta.push(`<span class="badge amber">跳转 ${(page.redirectChain || []).length} 次</span>`);
    if (page.server) meta.push(`<span class="badge">${esc(page.server)}</span>`);
    if (page.generator) meta.push(`<span class="badge purple">${esc(page.generator)}</span>`);
    if (page.charset) meta.push(`<span class="badge">${esc(page.charset)}</span>`);
    meta.push(`<span class="badge green">共 ${state.data.total} 项资源</span>`);
    el.meta.innerHTML = meta.join('');

    // 反爬 / 挑战页提示
    const warning = state.data.warning || '';
    if (warning) {
      el.meta.innerHTML += `<div class="extract-warning">${esc(warning)}</div>`;
    }
  }

  function renderChips() {
    const counts = state.data.counts || {};
    const chips = [`<button class="chip ${state.cat === 'all' ? 'active' : ''}" data-cat="all">全部 ${state.data.total}</button>`];
    CATS.forEach((cat) => {
      const n = counts[cat.key] || 0;
      if (!n) return;
      chips.push(`<button class="chip ${state.cat === cat.key ? 'active' : ''}" data-cat="${cat.key}">${cat.label} ${n}</button>`);
    });
    el.chips.innerHTML = chips.join('');
  }

  const ICONS = {
    videos: '<path d="M15 10l-6-3.5v7L15 10z"/><rect x="3" y="4.5" width="18" height="15" rx="3"/>',
    audios: '<path d="M9 18V6l10-2v12"/><circle cx="6.5" cy="18" r="2.5"/><circle cx="16.5" cy="16" r="2.5"/>',
    links: '<path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7-7l-1.2 1.2"/><path d="M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 0 0 7 7l1.2-1.2"/>',
    scripts: '<path d="M8 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h2M16 4h2a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-2"/><path d="M10 9l2 3-2 3"/>',
    styles: '<path d="M4 4h16v16H4z"/><path d="M4 9h16M9 9v11"/>',
    fonts: '<path d="M4 19h16M12 5v14M6 5h12"/>',
    iframes: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18"/>',
  };

  function thumbCard(item, checked) {
    return `<div class="res-card ${checked ? 'selected' : ''}" data-url="${esc(item.url)}">
      <label class="res-check"><input type="checkbox" data-url="${esc(item.url)}" ${checked ? 'checked' : ''} /></label>
      <span class="res-kind">${esc(item.source === 'favicon' ? 'ICON' : 'IMG')}</span>
      <div class="res-thumb">
        <img loading="lazy" src="${esc(item.url)}" alt="${esc(item.filename)}" referrerpolicy="no-referrer" />
      </div>
      <div class="res-body">
        <div class="res-name" title="${esc(item.url)}">${esc(item.filename)}</div>
        <div class="res-host">${esc(item.host)}</div>
        <div class="res-tools">
          <button data-act="open">打开</button>
          <button data-act="copy">复制</button>
          <button data-act="download">下载</button>
        </div>
      </div>
    </div>`;
  }

  function rowCard(item, checked) {
    const cat = CATS.find((c) => c.key === item.category) || { tag: '?' };
    const icon = ICONS[item.category] || '<circle cx="12" cy="12" r="8"/>';
    return `<div class="res-row" data-url="${esc(item.url)}">
      <input type="checkbox" class="row-check" data-url="${esc(item.url)}" ${checked ? 'checked' : ''}
        style="accent-color:var(--accent);width:13px;height:13px;flex-shrink:0" />
      <div class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
        stroke-linecap="round" stroke-linejoin="round">${icon}</svg></div>
      <div class="txt">
        <div class="name">${esc(item.filename)} <span style="color:var(--dim);font-size:10px">${esc(cat.tag)}</span></div>
        <div class="url" title="${esc(item.url)}">${esc(item.url)}</div>
      </div>
      <div class="res-tools">
        <button data-act="open">打开</button>
        <button data-act="copy">复制</button>
      </div>
    </div>`;
  }

  function renderResources() {
    const items = filtered();
    el.resTotal.textContent = state.data.total;
    el.selectedMeta.textContent = `已选 ${state.selected.size}`;

    if (!items.length) {
      el.list.innerHTML = `<div class="empty-state" style="margin-top:14px;padding:38px 16px">
        <h3>没有匹配的资源</h3><p>试试切换分类或清空筛选关键词。</p></div>`;
      return;
    }

    const parts = [];
    const groups = state.cat === 'all'
      ? CATS.filter((cat) => (state.data.counts || {})[cat.key])
      : CATS.filter((cat) => cat.key === state.cat);

    groups.forEach((cat) => {
      const list = items.filter((item) => item.category === cat.key);
      if (!list.length) return;
      parts.push(`<div class="card-title" style="margin:14px 0 8px">${cat.label}
        <span class="right">${list.length}</span></div>`);
      if (cat.key === 'images') {
        parts.push(`<div class="res-grid">${list.map((item) => thumbCard(item, state.selected.has(item.url))).join('')}</div>`);
      } else {
        parts.push(`<div class="res-row-list">${list.map((item) => rowCard(item, state.selected.has(item.url))).join('')}</div>`);
      }
    });
    el.list.innerHTML = parts.join('');
  }

  function renderAll() {
    renderPage();
    renderChips();
    renderResources();
    renderSource();
    renderDeepPages();
    renderExposed();
  }

  function renderDeepPages() {
    if (!state.data) return;
    const pages = state.data.pages || [];
    if (state.mode === 'deep' && pages.length) {
      el.deepPages.classList.remove('hidden');
      el.deepPageCount.textContent = pages.length;
      el.deepPagesList.innerHTML = pages
        .map((p) => `<a href="${esc(p.url)}" target="_blank" rel="noopener" title="${esc(p.url)}">${esc((p.title || p.url).slice(0, 48))}</a>`)
        .join('');
    } else {
      el.deepPages.classList.add('hidden');
    }
  }

  function renderExposed() {
    if (!state.data || !el.exposedList) return;
    const items = state.data.exposed || [];
    const robots = state.data.robotsDisallow || [];
    el.expTotal.textContent = items.length;
    el.exposedMeta.textContent = items.length
      ? `命中 ${items.length} 项，建议立即确认并处置`
      : '已探测 16 个常见泄露路径，全部未命中';
    el.exposedList.innerHTML = items.length
      ? items.map((it) => `
        <div class="exposed-row">
          <div class="exposed-head">
            <span class="exposed-path">/${esc(it.path)}</span>
            <span class="exposed-size">${it.size >= 1024 ? (it.size / 1024).toFixed(1) + ' KB' : it.size + ' B'}</span>
            <a class="exposed-open" href="${esc(it.url)}" target="_blank" rel="noopener">打开</a>
          </div>
          <div class="exposed-desc">${esc(it.desc)}</div>
          <div class="exposed-preview">${esc(it.preview)}</div>
        </div>`).join('')
      : '<div class="exposed-empty">没有发现暴露的备份、配置文件或源码目录。</div>';
    if (robots.length) {
      el.robotsBlock.classList.remove('hidden');
      el.robotsList.innerHTML = robots.map((p) => `<span class="robot-chip">${esc(p)}</span>`).join('');
    } else {
      el.robotsBlock.classList.add('hidden');
    }
  }

  function renderSource() {
    if (!state.data) return;
    const html = state.data.html || '';
    el.sourceCode.textContent = html || '（未返回 HTML 源码）';
    el.sourceMeta.textContent = `${html.length.toLocaleString('en-US')} 字符${
      state.data.htmlTruncated ? '，已截断' : ''}`;
  }

  function previewHtml() {
    const page = state.data.page || {};
    let html = state.data.html || '';
    html = html
      .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
      .replace(/<script\b[^>]*\/?>/gi, '')
      .replace(/\son[a-z]+\s*=\s*"[^"]*"/gi, '')
      .replace(/\son[a-z]+\s*=\s*'[^']*'/gi, '')
      .replace(/\son[a-z]+\s*=\s*[^\s>]+/gi, '')
      .replace(/(href|src)\s*=\s*(["'])\s*javascript:[^"']*\2/gi, '$1="#"');
    const base = `<base href="${esc(page.url || '')}" />`;
    if (/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, (m) => m + base);
    return `<!DOCTYPE html><html><head>${base}</head><body>${html}</body></html>`;
  }

  function selectTab(name) {
    state.tab = name;
    NS.$$('.sub-tab', el.tabs).forEach((tab) => tab.classList.toggle('active', tab.dataset.tab === name));
    NS.$$('.sub-panel', el.result).forEach((panel) => {
      panel.classList.toggle('active', panel.id === `extract-${name}`);
    });
    // 深度抓取没有单页 HTML 源码与预览，只显示资源标签
    NS.$$('.sub-tab', el.tabs).forEach((tab) => {
      const hide = state.mode === 'deep' && tab.dataset.tab !== 'resources';
      tab.style.display = hide ? 'none' : '';
    });
    if (name === 'preview' && !state.previewReady) {
      el.previewFrame.srcdoc = previewHtml();
      state.previewReady = true;
    }
  }

  async function run(urlOverride) {
    if (running) return;
    const url = (urlOverride !== undefined ? urlOverride : el.input.value || '').trim();
    if (!url) {
      setError('请输入要提取资源的页面地址');
      el.input.focus();
      return;
    }
    if (urlOverride !== undefined) el.input.value = url;
    running = true;
    setError('');
    show('loading');
    NS.setLoading(el.btn, true, '提取中...');
    try {
      const data = await NS.api(`/api/tools/extract?${NS.qs({ url, html: 'true' })}`);
      state.data = data;
      state.mode = 'extract';
      state.cat = 'all';
      state.search = '';
      state.selected = new Set();
      state.previewReady = false;
      el.search.value = '';
      el.previewFrame.removeAttribute('srcdoc');
      show('result');
      renderAll();
      selectTab('resources');
    } catch (err) {
      show('empty');
      setError(err.message || '提取失败');
    } finally {
      running = false;
      NS.setLoading(el.btn, false);
    }
  }

  async function runDeep() {
    if (running) return;
    const url = (el.input.value || '').trim();
    if (!url) {
      setError('请输入要顺藤摸瓜的页面地址');
      el.input.focus();
      return;
    }
    const depth = parseInt(el.deepDepth.value, 10) || 2;
    running = true;
    setError('');
    show('loading');
    NS.setLoading(el.deepBtn, true, '摸瓜中...');
    try {
      const data = await NS.api('/api/tools/deep-extract', {
        method: 'POST',
        body: { url, depth, max_pages: 25 },
      });
      state.data = data;
      state.mode = 'deep';
      state.cat = 'all';
      state.search = '';
      state.selected = new Set();
      state.previewReady = false;
      el.search.value = '';
      el.previewFrame.removeAttribute('srcdoc');
      show('result');
      renderAll();
      selectTab('resources');
    } catch (err) {
      show('empty');
      setError(err.message || '顺藤摸瓜失败');
    } finally {
      running = false;
      NS.setLoading(el.deepBtn, false);
    }
  }

  function targets() {
    const items = filtered();
    const picked = items.filter((item) => state.selected.has(item.url));
    return picked.length ? picked : items;
  }

  async function pack() {
    const items = targets();
    if (!items.length) {
      NS.toast('没有可打包的资源', true);
      return;
    }
    if (items.length > 60) {
      NS.toast('单次最多打包 60 个资源，请先筛选或勾选', true);
      return;
    }
    NS.setLoading(el.zip, true, '打包中...');
    try {
      if (NS.localMode && NS.local) {
        const blob = await NS.local.packZip(
          items.map((item) => ({ url: item.url, category: item.category })),
          (state.data.page && state.data.page.title) || 'resources'
        );
        NS.downloadBlob(blob, `resources-${Date.now()}.zip`);
        NS.toast(`已打包 ${items.length} 个资源`);
        return;
      }
      const resp = await fetch('/api/tools/package', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename: (state.data.page && state.data.page.title) || 'resources',
          items: items.map((item) => ({
            url: item.url,
            filename: item.filename,
            category: item.category,
          })),
        }),
      });
      if (!resp.ok) {
        let message = `打包失败（HTTP ${resp.status}）`;
        try {
          const data = await resp.json();
          if (data && data.detail) message = data.detail;
        } catch (err) { /* 忽略 */
        }
        throw new Error(message);
      }
      const blob = await resp.blob();
      const name = `resources-${Date.now()}.zip`;
      NS.downloadBlob(blob, name);
      NS.toast(`已打包 ${items.length} 个资源`);
    } catch (err) {
      NS.toast(err.message || '打包失败', true);
    } finally {
      NS.setLoading(el.zip, false);
    }
  }

  function bind() {
    el.btn.addEventListener('click', () => run());
    el.deepBtn.addEventListener('click', () => runDeep());
    el.input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') run();
    });
    el.clear.addEventListener('click', () => {
      el.input.value = '';
      el.input.focus();
      setError('');
      show('empty');
    });
    if (el.examples) {
      el.examples.addEventListener('click', (event) => {
        const chip = event.target.closest('.chip');
        if (!chip) return;
        el.input.value = chip.dataset.url || '';
        run();
      });
    }

    el.tabs.addEventListener('click', (event) => {
      const tab = event.target.closest('.sub-tab');
      if (tab) selectTab(tab.dataset.tab);
    });

    el.chips.addEventListener('click', (event) => {
      const chip = event.target.closest('.chip');
      if (!chip) return;
      state.cat = chip.dataset.cat;
      renderChips();
      renderResources();
    });

    el.search.addEventListener('input', NS.debounce(() => {
      state.search = el.search.value;
      renderResources();
    }, 140));

    el.list.addEventListener('change', (event) => {
      const box = event.target.closest('input[type=checkbox]');
      if (!box) return;
      const url = box.dataset.url;
      if (box.checked) state.selected.add(url);
      else state.selected.delete(url);
      const card = box.closest('.res-card');
      if (card) card.classList.toggle('selected', box.checked);
      el.selectedMeta.textContent = `已选 ${state.selected.size}`;
    });

    el.list.addEventListener('click', async (event) => {
      const button = event.target.closest('button[data-act]');
      if (!button) return;
      event.preventDefault();
      const row = button.closest('[data-url]');
      const url = row && row.dataset.url;
      if (!url) return;
      const act = button.dataset.act;
      if (act === 'open') window.open(url, '_blank', 'noopener');
      else if (act === 'copy') {
        const ok = await NS.copyText(url);
        NS.toast(ok ? '链接已复制' : '复制失败', !ok);
      } else if (act === 'download') {
        const link = document.createElement('a');
        link.href = url;
        link.download = '';
        link.target = '_blank';
        link.rel = 'noopener';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      }
    });

    el.list.addEventListener('error', (event) => {
      const img = event.target;
      if (!(img instanceof HTMLImageElement)) return;
      const thumb = img.closest('.res-thumb');
      if (thumb) {
        thumb.innerHTML = '<span class="ph"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="4.5" width="18" height="15" rx="2.5"/><path d="M3 15l5-4 4 3 3-2 6 5"/><circle cx="9" cy="9" r="1.4"/></svg></span>';
      }
    }, true);

    el.selectAll.addEventListener('click', () => {
      const items = filtered();
      const allSelected = items.every((item) => state.selected.has(item.url));
      items.forEach((item) => {
        if (allSelected) state.selected.delete(item.url);
        else state.selected.add(item.url);
      });
      renderResources();
    });

    el.copy.addEventListener('click', async () => {
      const items = targets();
      if (!items.length) return;
      const ok = await NS.copyText(items.map((item) => item.url).join('\n'));
      NS.toast(ok ? `已复制 ${items.length} 条链接` : '复制失败', !ok);
    });

    el.csv.addEventListener('click', () => {
      const items = targets();
      if (!items.length) return;
      const rows = [['分类', '文件名', '主机', '来源', '地址']];
      items.forEach((item) => rows.push([item.category, item.filename, item.host, item.source, item.url]));
      NS.downloadText('\ufeff' + NS.csv(rows), `resources-${state.data.page.url ? 'page' : 'export'}.csv`, 'text/csv;charset=utf-8');
    });

    el.json.addEventListener('click', () => {
      if (!state.data) return;
      const payload = Object.assign({}, state.data);
      delete payload.html;
      NS.downloadText(JSON.stringify(payload, null, 2), 'resources.json', 'application/json;charset=utf-8');
    });

    el.zip.addEventListener('click', pack);

    if (el.exposedCopy) {
      el.exposedCopy.addEventListener('click', async () => {
        const items = (state.data && state.data.exposed) || [];
        if (!items.length) return NS.toast('没有可复制的地址', true);
        const ok = await NS.copyText(items.map((x) => x.url).join('\n'));
        NS.toast(ok ? `已复制 ${items.length} 条地址` : '复制失败', !ok);
      });
    }

    el.sourceCopy.addEventListener('click', async () => {
      const ok = await NS.copyText(state.data ? state.data.html || '' : '');
      NS.toast(ok ? '源码已复制' : '复制失败', !ok);
    });

    el.sourceDownload.addEventListener('click', () => {
      if (!state.data) return;
      NS.downloadText(state.data.html || '', 'page.html', 'text/html;charset=utf-8');
    });

    el.open.addEventListener('click', () => {
      if (state.data && state.data.page.url) window.open(state.data.page.url, '_blank', 'noopener');
    });

    el.report.addEventListener('click', () => {
      if (!state.data) return;
      const payload = Object.assign({}, state.data);
      delete payload.html;
      NS.downloadText(JSON.stringify(payload, null, 2), 'extract-report.json', 'application/json;charset=utf-8');
    });
  }

  NS.extract = {
    init() {
      grab();
      bind();
    },
  };
})();
