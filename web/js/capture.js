/* 抓包分析 */
(function () {
  'use strict';

  const NS = window.NS;
  const $ = NS.$;
  const esc = NS.esc;
  const PAGE_SIZE = 200;

  const el = {};
  const state = {
    sid: null,
    sessions: [],
    interfaces: [],
    packets: [],
    total: 0,
    captured: 0,
    offset: 0,
    tail: true,
    filter: '',
    selected: null,
    detail: null,
    detailTab: 'tree',
    hexRange: null,
    ctab: 'packets',
    ws: null,
    wsSid: null,
    wsFilter: null,
    reconnectTimer: null,
    followNum: null,
    visible: false,
  };
  let loadingPage = false;
  let statsLoading = false;

  function grab() {
    el.iface = $('#ifaceSelect');
    el.start = $('#startBtn');
    el.demo = $('#demoBtn');
    el.status = $('#capStatus');
    el.statusText = $('#capStatusText');
    el.importFile = $('#importFile');
    el.importBtn = $('#importBtn');
    el.exportBtn = $('#exportBtn');
    el.deleteBtn = $('#deleteBtn');
    el.filter = $('#filterInput');
    el.filterClear = $('#filterClear');
    el.quick = $('#quickFilters');
    el.autoScroll = $('#autoScroll');
    el.sessionCount = $('#sessionCount');
    el.sessionList = $('#sessionList');
    el.packetCount = $('#packetCount');
    el.packetHint = $('#packetHint');
    el.tableWrap = $('#packetTableWrap');
    el.packetBody = $('#packetBody');
    el.packetEmpty = $('#packetEmpty');
    el.packetEmptyText = $('#packetEmptyText');
    el.prev = $('#prevPage');
    el.next = $('#nextPage');
    el.pageInfo = $('#pageInfo');
    el.pageStat = $('#pageStat');
    el.viewTabs = $('.view-tabs');
    el.ctabPackets = $('#ctab-packets');
    el.ctabStats = $('#ctab-stats');
    el.statsScroll = $('#statsScroll');
    el.statCards = $('#statCards');
    el.timelineMeta = $('#timelineMeta');
    el.timeline = $('#timelineChart');
    el.protoBars = $('#protoBars');
    el.talkers = $('#talkersBody');
    el.convMeta = $('#convMeta');
    el.convBody = $('#convBody');
    el.detailPanel = $('#detailPanel');
    el.detailResizer = $('#detailResizer');
    el.detailTitle = $('#detailTitle');
    el.detailTabs = $('#detailTabs');
    el.detailClose = $('#detailClose');
    el.tree = $('#dtab-tree');
    el.hex = $('#dtab-hex');
    el.follow = $('#dtab-follow');
    el.ai = $('#dtab-ai');
    el.footerInfo = $('#capFooterInfo');
    el.footerFilter = $('#capFooterFilter');
  }

  /* ------------------------------------------------------------ 会话 */

  function activeSession() {
    return state.sessions.find((item) => item.id === state.sid) || null;
  }

  function statusLabel(status) {
    return {
      idle: '未开始',
      starting: '启动中',
      capturing: '抓包中',
      stopped: '已停止',
      error: '出错',
    }[status] || status || '未知';
  }

  function statusClass(status) {
    if (status === 'capturing' || status === 'starting') return 'live';
    if (status === 'error') return 'err';
    if (status === 'stopped') return 'done';
    return '';
  }

  function canStop(session) {
    return !!session && (session.status === 'capturing' || session.status === 'starting');
  }

  function renderSessions() {
    el.sessionCount.textContent = state.sessions.length;
    if (!state.sessions.length) {
      el.sessionList.innerHTML = '<div style="padding:14px;font-size:11.5px;color:var(--dim);line-height:1.6">还没有会话，点击「开始抓包」或「演示抓包」创建。</div>';
      return;
    }
    el.sessionList.innerHTML = state.sessions.map((session) => `
      <div class="session-item ${session.id === state.sid ? 'active' : ''}" data-id="${esc(session.id)}">
        <div class="s-top">
          <span class="s-dot ${statusClass(session.status)}"></span>
          <span class="s-name" title="${esc(session.name)}">${esc(session.name)}</span>
        </div>
        <div class="s-meta">
          <span>${esc(session.kind === 'demo' ? '演示' : session.kind === 'file' ? '文件' : session.interface)}</span>
          <span>${NS.fmtNum(session.packets)} 包</span>
          <span>${NS.fmtBytes(session.bytes)}</span>
        </div>
      </div>`).join('');
  }

  function updateChrome() {
    const session = activeSession();
    if (!session) {
      el.status.className = 'cap-status';
      el.statusText.textContent = '未开始';
      el.footerInfo.textContent = '未选择会话';
      el.start.textContent = '开始抓包';
      el.start.classList.remove('stop');
      el.exportBtn.disabled = true;
      el.deleteBtn.disabled = true;
      return;
    }
    const cls = statusClass(session.status);
    el.status.className = `cap-status ${cls}`;
    el.statusText.textContent = statusLabel(session.status) + (session.status === 'capturing' ? `，${NS.fmtNum(session.packets)} 个包` : '');
    el.start.textContent = canStop(session) ? '停止抓包' : '开始抓包';
    el.start.classList.toggle('stop', canStop(session));
    el.exportBtn.disabled = false;
    el.deleteBtn.disabled = false;
    el.footerInfo.textContent = `会话：${session.name}，${session.kind === 'demo' ? '演示流量' : session.interface}，${
      statusLabel(session.status)}，${NS.fmtNum(session.packets)} 个包，${NS.fmtBytes(session.bytes)}`;
    el.footerFilter.textContent = state.filter ? `过滤器：${state.filter}` : '无过滤器';
    if (session.kind === 'live' && session.status === 'error' && session.error) {
      el.packetEmptyText.textContent = session.error;
    } else {
      el.packetEmptyText.textContent = session.packets
        ? '当前过滤器下没有匹配的数据包'
        : '还没有数据包，点击「开始抓包」或「演示抓包」';
    }
  }

  async function loadSessions(selectId) {
    try {
      const data = await NS.api('/api/sessions');
      state.sessions = data.sessions || [];
      renderSessions();
      let target = selectId || state.sid;
      if (!target || !state.sessions.some((item) => item.id === target)) {
        target = state.sessions.length ? state.sessions[0].id : null;
      }
      if (target && target !== state.sid) {
        await selectSession(target);
      } else {
        updateChrome();
      }
    } catch (err) {
      NS.toast(err.message || '会话加载失败', true);
    }
  }

  async function selectSession(sid) {
    state.sid = sid;
    state.total = 0;
    state.offset = 0;
    state.tail = true;
    state.packets = [];
    state.selected = null;
    state.detail = null;
    state.hexRange = null;
    state.followNum = null;
    el.packetBody.innerHTML = '';
    el.packetCount.textContent = '0';
    resetDetail();
    renderSessions();
    updateChrome();
    try {
      await loadPage(true);
    } catch (err) {
      NS.toast(err.message || '数据包加载失败', true);
    }
    openWS();
    if (state.ctab === 'stats') loadStats();
  }

  /* ------------------------------------------------------------ 数据包分页 */

  function packetRow(packet) {
    const color = NS.protoColor(packet.color, packet.proto);
    return `<tr data-num="${packet.num}" class="${packet.num === state.selected ? 'selected' : ''}">
      <td class="num">${packet.num}</td>
      <td>${NS.clock(packet.ts)}</td>
      <td class="addr">${esc(packet.src)}</td>
      <td class="addr">${esc(packet.dst)}</td>
      <td><span class="proto" style="color:${color}">${esc(packet.proto)}</span></td>
      <td class="len">${packet.len}</td>
      <td class="info">${esc(packet.info)}</td>
    </tr>`;
  }

  async function loadPage() {
    if (!state.sid || loadingPage) return;
    loadingPage = true;
    const params = { limit: PAGE_SIZE, filter: state.filter };
    if (state.tail) params.tail = 'true';
    else params.offset = state.offset;
    try {
      const data = await NS.api(`/api/sessions/${state.sid}/packets?${NS.qs(params)}`);
      state.total = data.total;
      state.captured = data.captured;
      state.offset = data.offset;
      state.packets = data.packets || [];
      state.tail = state.offset + PAGE_SIZE >= state.total;
      const session = activeSession();
      if (session) session.packets = Math.max(session.packets || 0, data.captured);
      el.packetBody.innerHTML = state.packets.map(packetRow).join('');
      el.packetEmpty.classList.toggle('hidden', state.packets.length !== 0);
      el.packetCount.textContent = NS.fmtNum(state.captured);
      el.packetHint.textContent = data.truncated ? '内存中仅保留最近 20 万个包' : '';
      updatePager();
      updateChrome();
      if (el.autoScroll.checked && state.tail) {
        el.tableWrap.scrollTop = el.tableWrap.scrollHeight;
      }
    } catch (err) {
      NS.toast(err.message || '数据包加载失败', true);
      throw err;
    } finally {
      loadingPage = false;
    }
  }

  function updatePager() {
    const pages = Math.max(1, Math.ceil(state.total / PAGE_SIZE));
    const pageNo = state.tail ? pages : Math.floor(state.offset / PAGE_SIZE) + 1;
    el.pageInfo.textContent = `第 ${pageNo} / ${pages} 页`;
    const singlePage = state.total <= PAGE_SIZE;
    el.prev.disabled = singlePage || state.offset <= 0;
    el.next.disabled = singlePage || state.offset + PAGE_SIZE >= state.total;
    el.pageStat.textContent = `显示 ${state.packets.length}，匹配 ${NS.fmtNum(state.total)}，已捕获 ${NS.fmtNum(state.captured)}`;
  }

  async function applyFilter(text) {
    const value = (text || '').trim();
    const previous = state.filter;
    state.filter = value;
    state.tail = true;
    state.offset = 0;
    try {
      await loadPage();
      el.footerFilter.textContent = value ? `过滤器：${value}` : '无过滤器';
      openWS();
    } catch (err) {
      state.filter = previous;
      el.filter.value = previous;
      NS.toast(err.message || '过滤器语法错误', true);
    }
  }

  /* ------------------------------------------------------------ WebSocket */

  function closeWS() {
    clearTimeout(state.reconnectTimer);
    state.reconnectTimer = null;
    if (state.ws) {
      const ws = state.ws;
      state.ws = null;
      ws.onclose = null;
      try {
        ws.close();
      } catch (err) { /* 忽略 */ }
    }
    state.wsSid = null;
    state.wsFilter = null;
  }

  function openWS() {
    if (!state.sid || !state.visible) return;
    if (state.wsSid === state.sid && state.wsFilter === state.filter && state.ws) return;
    closeWS();
    const last = state.packets.length ? state.packets[state.packets.length - 1].num : 0;
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${scheme}://${location.host}/ws/sessions/${state.sid}?since=${last}&filter=${encodeURIComponent(state.filter)}`;
    state.wsSid = state.sid;
    state.wsFilter = state.filter;
    let ws;
    try {
      ws = new WebSocket(url);
    } catch (err) {
      return;
    }
    state.ws = ws;

    ws.onmessage = (event) => {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch (err) {
        return;
      }
      if (data.type === 'error') {
        NS.toast(data.message || '实时连接出错', true);
        return;
      }
      if (data.type === 'packets') {
        const session = activeSession();
        if (session && data.packets.length) {
          session.packets = Math.max(session.packets, data.packets[data.packets.length - 1].num);
        }
        if (state.tail && el.autoScroll.checked) {
          scheduleReload();
        } else {
          updateChrome();
        }
        return;
      }
      if (data.type === 'status') {
        const session = activeSession();
        if (session) {
          session.status = data.status;
          if (typeof data.captured === 'number') session.packets = data.captured;
          session.error = data.error || null;
          if (data.status === 'error' && data.error) NS.toast(data.error, true);
          renderSessions();
          updateChrome();
        }
        if (data.status === 'stopped' || data.status === 'error') {
          closeWS();
          loadPage().catch(() => {});
        }
      }
    };

    ws.onclose = () => {
      if (state.ws !== ws) return;
      state.ws = null;
      state.wsSid = null;
      state.wsFilter = null;
      const session = activeSession();
      if (session && (session.status === 'capturing' || session.status === 'starting')) {
        clearTimeout(state.reconnectTimer);
        state.reconnectTimer = setTimeout(() => openWS(), 2500);
      }
    };
  }

  let reloadTimer = null;
  function scheduleReload() {
    if (reloadTimer) return;
    reloadTimer = setTimeout(() => {
      reloadTimer = null;
      loadPage().catch(() => {});
    }, 450);
  }

  /* ------------------------------------------------------------ 详情 */

  function resetDetail() {
    el.detailTitle.textContent = '未选择数据包';
    el.tree.innerHTML = `<div class="detail-placeholder">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/></svg>
      点击任意数据包查看协议详情，或在右侧「AI 分析」标签让模型解读</div>`;
    el.hex.innerHTML = '';
    el.follow.innerHTML = '<div class="detail-placeholder">点击「跟随流」重组 TCP 会话</div>';
    el.ai.innerHTML = '<div class="detail-placeholder">先点击一个数据包，再点此标签让 AI 分析</div>';
    state.detail = null;
    state.hexRange = null;
    state.followNum = null;
    el.detailPanel.style.display = 'flex';
  }

  async function selectPacket(num) {
    state.selected = num;
    NS.$$('#packetBody tr').forEach((row) => {
      row.classList.toggle('selected', Number(row.dataset.num) === num);
    });
    try {
      const detail = await NS.api(`/api/sessions/${state.sid}/packets/${num}`);
      state.detail = detail;
      state.hexRange = null;
      el.detailPanel.style.display = 'flex';
      el.detailTitle.textContent = `#${detail.num}，${detail.proto}，${detail.src} 到 ${detail.dst}，${detail.len} 字节`;
      renderTree(detail.tree || []);
      renderHex(detail.data || '');
      el.follow.innerHTML = '<div class="detail-placeholder">点击「跟随流」重组 TCP 会话</div>';
      el.ai.innerHTML = '<div class="detail-placeholder">点击「AI 分析」让模型解读这个数据包</div>';
      el.ai.dataset.loaded = '';
      state.followNum = null;
      if (state.detailTab === 'follow') loadFollow(num);
      setDetailTab(state.detailTab);
    } catch (err) {
      NS.toast(err.message || '数据包详情加载失败', true);
    }
  }

  function renderTree(nodes) {
    const build = (list) => list.map((node) => {
      const items = (node.items || []).map((item) => {
        const hasRange = Array.isArray(item.range) && item.range.length === 2;
        return `<div class="tree-item ${hasRange ? 'has-range' : ''}"
          ${hasRange ? `data-start="${item.range[0]}" data-end="${item.range[1]}"` : ''}>
          <span class="ti-name">${esc(item.name)}</span>
          <span class="ti-value">${esc(item.value)}</span>
        </div>`;
      }).join('');
      const children = build(node.children || []);
      return `<div class="tree-node">
        <div class="tree-head"><span class="caret">▾</span><span class="t-title"><b>${esc(node.title)}</b></span></div>
        <div class="tree-items">${items}${children}</div>
      </div>`;
    }).join('');
    el.tree.innerHTML = build(nodes) || '<div class="detail-placeholder">没有可展示的协议字段</div>';
  }

  function b64ToBytes(base64) {
    try {
      const binary = atob(base64);
      const out = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
      return out;
    } catch (err) {
      return new Uint8Array(0);
    }
  }

  function renderHex(base64) {
    const bytes = b64ToBytes(base64);
    if (!bytes.length) {
      el.hex.innerHTML = '<div class="detail-placeholder">没有字节数据</div>';
      return;
    }
    const lines = [];
    for (let offset = 0; offset < bytes.length; offset += 16) {
      const hex = [];
      const ascii = [];
      for (let i = 0; i < 16 && offset + i < bytes.length; i += 1) {
        const value = bytes[offset + i];
        hex.push(`<span class="hex-byte" data-off="${offset + i}">${value.toString(16).padStart(2, '0')}</span>`);
        ascii.push(`<span class="ch" data-off="${offset + i}">${
          value >= 32 && value < 127 ? esc(String.fromCharCode(value)) : '.'}</span>`);
      }
      lines.push(`<div class="hex-line">
        <span class="hex-off">${offset.toString(16).padStart(8, '0')}</span>
        <span class="hex-bytes">${hex.join('')}</span>
        <span class="hex-ascii">${ascii.join('')}</span>
      </div>`);
    }
    el.hex.innerHTML = `<div class="hex-wrap">${lines.join('')}</div>`;
    if (state.hexRange) applyHexHighlight();
  }

  function applyHexHighlight() {
    if (!state.hexRange) return;
    const [start, end] = state.hexRange;
    NS.$$('.hex-byte, .hex-ascii .ch', el.hex).forEach((node) => {
      const offset = Number(node.dataset.off);
      node.classList.toggle('hl', offset >= start && offset < end);
    });
  }

  function renderFollow(data) {
    const head = `<div class="follow-head">
      <span class="ep">A：${esc(data.endpoints[0])}</span>
      <span class="ep">B：${esc(data.endpoints[1])}</span>
      <span>${data.segments.length} 段</span>
    </div>`;
    const segments = (data.segments || []).map((seg) => `
      <div class="follow-seg">
        <div class="seg-head">
          <span class="dir ${seg.dir === 'a2b' ? 'a2b' : 'b2a'}">${seg.dir === 'a2b' ? 'A 到 B' : 'B 到 A'}</span>
          <span>#${seg.num}</span><span>${seg.length} B</span>
        </div>
        <pre>${esc(seg.text)}</pre>
      </div>`).join('');
    el.follow.innerHTML = `<div class="follow-wrap">${head}${
      segments || '<div class="detail-placeholder">该流没有可显示的载荷</div>'}</div>`;
  }

  async function loadFollow(num) {
    el.follow.innerHTML = '<div class="detail-placeholder">正在重组 TCP 流...</div>';
    try {
      const data = await NS.api(`/api/sessions/${state.sid}/follow/${num}`);
      state.followNum = num;
      renderFollow(data);
    } catch (err) {
      el.follow.innerHTML = `<div class="detail-placeholder" style="color:#fca5a5">${esc(err.message || '无法跟随该数据流')}</div>`;
    }
  }

  function setDetailTab(name) {
    state.detailTab = name;
    NS.$$('button', el.detailTabs).forEach((btn) => btn.classList.toggle('active', btn.dataset.dtab === name));
    [el.tree, el.hex, el.follow, el.ai].forEach((panel) => panel.classList.remove('active'));
    const map = { tree: el.tree, hex: el.hex, follow: el.follow, ai: el.ai };
    if (map[name]) map[name].classList.add('active');
    if (name === 'follow' && state.selected && state.followNum !== state.selected) loadFollow(state.selected);
    if (name === 'hex' && state.hexRange) applyHexHighlight();
    if (name === 'ai' && state.selected && !el.ai.dataset.loaded) loadAIAnalysis(state.selected);
  }

  async function loadAIAnalysis(num) {
    el.ai.innerHTML = '<div class="detail-placeholder">正在让 AI 分析...</div>';
    el.ai.dataset.loaded = '1';
    try {
      const resp = await NS.api('/api/ai/analyze', { method: 'POST', body: { sid: state.sid, num } });
      el.ai.innerHTML = `<div class="ai-result">${esc(resp.analysis).replace(/\n/g, '<br>')}</div>`;
    } catch (err) {
      el.ai.innerHTML = `<div class="detail-placeholder" style="color:#fca5a5">${esc(err.message || 'AI 分析失败')}</div>`;
      el.ai.dataset.loaded = '';
    }
  }

  /* ------------------------------------------------------------ 统计 */

  async function loadStats() {
    if (!state.sid || statsLoading) return;
    statsLoading = true;
    try {
      const data = await NS.api(`/api/sessions/${state.sid}/stats`);
      renderStats(data);
    } catch (err) {
      /* 静默失败，下一轮重试 */
    } finally {
      statsLoading = false;
    }
  }

  function renderStats(data) {
    const cards = [
      ['数据包', NS.fmtNum(data.total)],
      ['总字节', NS.fmtBytes(data.bytes)],
      ['持续时间', NS.fmtDuration(data.duration)],
      ['平均速率', `${data.pps}<small> pps</small>`],
      ['TCP 流', NS.fmtNum(data.streams)],
    ];
    el.statCards.innerHTML = cards.map(([label, value]) =>
      `<div class="stat-card"><div class="label">${label}</div><div class="value">${value}</div></div>`).join('');

    el.timelineMeta.textContent = `总时长 ${NS.fmtDuration(data.duration)}，共 ${data.timeline.length} 段`;
    drawTimeline(data.timeline || []);

    const maxCount = Math.max(1, ...data.protocols.map((p) => p.count));
    const totalCount = data.protocols.reduce((sum, p) => sum + p.count, 0) || 1;
    el.protoBars.innerHTML = data.protocols.length
      ? data.protocols.map((proto) => {
        const pct = (proto.count / totalCount) * 100;
        const width = Math.max(2, (proto.count / maxCount) * 100);
        const color = NS.protoColor(proto.color, proto.name);
        return `<div class="proto-bar-row">
          <span class="pname">${esc(proto.name)}</span>
          <span class="bar"><i style="width:${width}%;background:${color}"></i></span>
          <span class="pval">${NS.fmtNum(proto.count)}，${pct.toFixed(1)}%</span>
        </div>`;
      }).join('')
      : '<div style="font-size:11.5px;color:var(--dim)">暂无数据</div>';

    el.talkers.innerHTML = data.talkers.length
      ? data.talkers.map((item) => `<tr><td>${esc(item.addr)}</td>
        <td>${NS.fmtNum(item.packets)}</td><td>${NS.fmtBytes(item.bytes)}</td></tr>`).join('')
      : '<tr><td colspan="3" style="color:var(--dim)">暂无数据</td></tr>';

    el.convMeta.textContent = `${data.conversations.length} 条`;
    el.convBody.innerHTML = data.conversations.length
      ? data.conversations.map((item) => `<tr>
        <td>${esc(item.endpointA)}</td><td>${esc(item.endpointB)}</td>
        <td style="color:${NS.protoColor(null, item.proto)}">${esc(item.proto)}</td>
        <td>${NS.fmtNum(item.packets)}</td><td>${NS.fmtBytes(item.bytes)}</td></tr>`).join('')
      : '<tr><td colspan="5" style="color:var(--dim)">暂无 TCP 会话</td></tr>';
  }

  function drawTimeline(timeline) {
    const canvas = el.timeline;
    if (!canvas) return;
    const wrap = canvas.parentElement;
    const width = Math.max(wrap.clientWidth || 600, 240);
    const height = Math.max(wrap.clientHeight || 150, 100);
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    const padL = 42;
    const padR = 8;
    const padT = 8;
    const padB = 18;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;

    const max = Math.max(1, ...timeline.map((item) => item.packets));
    ctx.font = '10px ui-monospace, Menlo, Consolas, monospace';
    ctx.strokeStyle = '#1b2739';
    ctx.fillStyle = '#5f7085';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 3; i += 1) {
      const y = padT + (plotH / 3) * i;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(width - padR, y);
      ctx.stroke();
      const value = Math.round(max - (max / 3) * i);
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      ctx.fillText(String(value), padL - 6, y);
    }

    if (!timeline.length) {
      ctx.textAlign = 'center';
      ctx.fillText('暂无流量', padL + plotW / 2, padT + plotH / 2);
      return;
    }

    const barW = Math.max(1.5, plotW / timeline.length - 1.5);
    timeline.forEach((item, index) => {
      const x = padL + (plotW / timeline.length) * index;
      const barH = Math.max(1, (item.packets / max) * plotH);
      const y = padT + plotH - barH;
      const gradient = ctx.createLinearGradient(0, y, 0, padT + plotH);
      gradient.addColorStop(0, '#38bdf8');
      gradient.addColorStop(1, 'rgba(56,189,248,.25)');
      ctx.fillStyle = gradient;
      ctx.fillRect(x, y, barW, barH);
    });

    ctx.fillStyle = '#5f7085';
    ctx.textBaseline = 'top';
    ctx.textAlign = 'left';
    ctx.fillText('0 s', padL, padT + plotH + 5);
    if (timeline.length > 1) {
      ctx.textAlign = 'right';
      const span = timeline[timeline.length - 1].t - timeline[0].t;
      ctx.fillText(`${span.toFixed(1)} s`, width - padR, padT + plotH + 5);
    }
  }

  function switchCtab(name) {
    state.ctab = name;
    NS.$$('button', el.viewTabs).forEach((btn) => btn.classList.toggle('active', btn.dataset.ctab === name));
    el.ctabPackets.classList.toggle('active', name === 'packets');
    el.ctabStats.classList.toggle('active', name === 'stats');
    if (name === 'stats') loadStats();
  }

  /* ------------------------------------------------------------ 工具栏动作 */

  async function loadInterfaces() {
    try {
      const data = await NS.api('/api/interfaces');
      state.interfaces = (data.interfaces || []).sort((a, b) => {
        const rank = (item) => (item.name === 'lo' ? 2 : item.state === 'up' ? 0 : 1);
        return rank(a) - rank(b);
      });
      const options = ['<option value="demo">演示流量（无需权限）</option>'];
      state.interfaces.forEach((iface) => {
        const stateText = iface.state === 'up' ? '已连接' : iface.state;
        const addr = iface.ipv4 || (iface.ipv6 && iface.ipv6[0]) || '无地址';
        options.push(`<option value="${esc(iface.name)}">${esc(iface.name)}，${esc(addr)}，${esc(stateText)}</option>`);
      });
      el.iface.innerHTML = options.join('');
    } catch (err) {
      /* 网卡列表失败不影响演示模式 */
    }
  }

  async function startCapture() {
    const session = activeSession();
    if (canStop(session)) {
      try {
        await NS.api(`/api/sessions/${state.sid}/stop`, { method: 'POST' });
        NS.toast('抓包已停止');
        await loadSessions(state.sid);
      } catch (err) {
        NS.toast(err.message || '停止失败', true);
      }
      return;
    }
    const iface = el.iface.value || 'demo';
    const kind = iface === 'demo' ? 'demo' : 'live';
    NS.setLoading(el.start, true, '启动中...');
    try {
      const data = await NS.api('/api/sessions', { method: 'POST', body: { interface: iface, kind } });
      await loadSessions(data.session.id);
      NS.toast(kind === 'demo' ? '演示抓包已开始' : `已在 ${iface} 上开始抓包`);
    } catch (err) {
      NS.toast(err.message || '启动失败', true);
    } finally {
      NS.setLoading(el.start, false);
      updateChrome();
    }
  }

  async function startDemo() {
    NS.setLoading(el.demo, true, '启动中...');
    try {
      const name = `演示抓包 ${new Date().toLocaleTimeString('zh-CN', { hour12: false })}`;
      const data = await NS.api('/api/sessions', {
        method: 'POST',
        body: { interface: 'demo', kind: 'demo', name },
      });
      await loadSessions(data.session.id);
      NS.toast('演示抓包已开始');
    } catch (err) {
      NS.toast(err.message || '启动失败', true);
    } finally {
      NS.setLoading(el.demo, false);
    }
  }

  async function deleteSession() {
    if (!state.sid) return;
    const session = activeSession();
    if (!window.confirm(`确定删除会话「${session ? session.name : state.sid}」？抓包文件也会一并删除。`)) return;
    try {
      await NS.api(`/api/sessions/${state.sid}`, { method: 'DELETE' });
      closeWS();
      state.sid = null;
      NS.toast('会话已删除');
      await loadSessions();
    } catch (err) {
      NS.toast(err.message || '删除失败', true);
    }
  }

  async function importFile(file) {
    if (!file) return;
    NS.setLoading(el.importBtn, true, '导入中...');
    try {
      const buffer = await file.arrayBuffer();
      const resp = await fetch('/api/import', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'x-filename': encodeURIComponent(file.name),
        },
        body: buffer,
      });
      const raw = await resp.text();
      let data = null;
      try {
        data = raw ? JSON.parse(raw) : null;
      } catch (err) {
        data = null;
      }
      if (!resp.ok) throw new Error((data && data.detail) || `导入失败（HTTP ${resp.status}）`);
      await loadSessions(data.session.id);
      NS.toast(`已导入 ${file.name}`);
    } catch (err) {
      NS.toast(err.message || '导入失败', true);
    } finally {
      NS.setLoading(el.importBtn, false);
    }
  }

  function exportCapture() {
    if (!state.sid) return;
    const params = NS.qs({ filter: state.filter });
    const link = document.createElement('a');
    link.href = `/api/sessions/${state.sid}/export${params ? `?${params}` : ''}`;
    link.download = '';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    NS.toast('正在导出 pcap 文件');
  }

  /* ------------------------------------------------------------ 事件绑定 */

  function bind() {
    el.sessionList.addEventListener('click', (event) => {
      const item = event.target.closest('.session-item');
      if (!item || item.dataset.id === state.sid) return;
      selectSession(item.dataset.id);
    });

    el.start.addEventListener('click', startCapture);
    el.demo.addEventListener('click', startDemo);
    el.deleteBtn.addEventListener('click', deleteSession);
    el.exportBtn.addEventListener('click', exportCapture);
    el.importBtn.addEventListener('click', () => el.importFile.click());
    el.importFile.addEventListener('change', () => {
      const file = el.importFile.files && el.importFile.files[0];
      el.importFile.value = '';
      importFile(file);
    });

    el.filter.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') applyFilter(el.filter.value);
    });
    el.filterClear.addEventListener('click', () => {
      el.filter.value = '';
      applyFilter('');
    });
    el.quick.addEventListener('click', (event) => {
      const button = event.target.closest('button[data-filter]');
      if (!button) return;
      NS.$$('button', el.quick).forEach((item) =>
        item.style.color = item === button ? 'var(--accent)' : '');
      el.filter.value = button.dataset.filter || '';
      applyFilter(el.filter.value);
    });

    el.packetBody.addEventListener('click', (event) => {
      const row = event.target.closest('tr[data-num]');
      if (!row) return;
      selectPacket(Number(row.dataset.num));
    });

    el.prev.addEventListener('click', () => {
      if (state.offset <= 0) return;
      state.tail = false;
      state.offset = Math.max(state.offset - PAGE_SIZE, 0);
      if (state.offset + PAGE_SIZE >= state.total) state.tail = true;
      loadPage();
    });
    el.next.addEventListener('click', () => {
      state.offset += PAGE_SIZE;
      state.tail = state.offset + PAGE_SIZE >= state.total;
      loadPage();
    });

    el.viewTabs.addEventListener('click', (event) => {
      const button = event.target.closest('button[data-ctab]');
      if (button) switchCtab(button.dataset.ctab);
    });

    el.detailTabs.addEventListener('click', (event) => {
      const button = event.target.closest('button[data-dtab]');
      if (button) setDetailTab(button.dataset.dtab);
    });

    el.detailClose.addEventListener('click', () => {
      el.detailPanel.style.display = 'none';
    });

    el.tree.addEventListener('click', (event) => {
      const item = event.target.closest('.tree-item');
      if (item && item.dataset.start !== undefined) {
        state.hexRange = [Number(item.dataset.start), Number(item.dataset.end)];
        applyHexHighlight();
        return;
      }
      const head = event.target.closest('.tree-head');
      if (head) {
        const node = head.closest('.tree-node');
        if (node) node.classList.toggle('collapsed');
      }
    });

    /* 详情面板高度拖拽 */
    let drag = null;
    el.detailResizer.addEventListener('mousedown', (event) => {
      event.preventDefault();
      drag = { startY: event.clientY, startH: el.detailPanel.offsetHeight };
      document.body.style.userSelect = 'none';
      document.body.style.cursor = 'ns-resize';
    });
    document.addEventListener('mousemove', (event) => {
      if (!drag) return;
      const delta = drag.startY - event.clientY;
      const max = el.detailPanel.parentElement.clientHeight - 120;
      const height = Math.max(120, Math.min(drag.startH + delta, max));
      el.detailPanel.style.height = `${height}px`;
    });
    document.addEventListener('mouseup', () => {
      if (!drag) return;
      drag = null;
      document.body.style.userSelect = '';
      document.body.style.cursor = '';
      if (state.ctab === 'stats') loadStats();
    });

    window.addEventListener('resize', NS.debounce(() => {
      if (state.ctab === 'stats') loadStats();
    }, 200));

    /* 定时刷新会话列表，保持状态同步；当前会话被删除时自动切换或清空 */
    setInterval(() => {
      if (!state.visible) return;
      NS.api('/api/sessions').then((data) => {
        state.sessions = data.sessions || [];
        renderSessions();
        if (state.sid && !state.sessions.some((item) => item.id === state.sid)) {
          if (state.sessions.length) {
            selectSession(state.sessions[0].id);
          } else {
            state.sid = null;
            state.total = 0;
            state.packets = [];
            state.selected = null;
            el.packetBody.innerHTML = '';
            el.packetCount.textContent = '0';
            el.pageStat.textContent = '还没有会话';
            resetDetail();
            updateChrome();
          }
          return;
        }
        updateChrome();
      }).catch(() => {});
    }, 7000);

    /* WebSocket 不可用时的轮询兜底 */
    setInterval(() => {
      if (!state.visible) return;
      const session = activeSession();
      if (!session) return;
      const live = session.status === 'capturing' || session.status === 'starting';
      if (!live) return;
      if (!state.ws && state.tail) loadPage().catch(() => {});
      if (state.ctab === 'stats') loadStats();
    }, 1600);
  }

  NS.capture = {
    init() {
      grab();
      bind();
      resetDetail();
      loadInterfaces();
      loadSessions();
    },
    refresh() {
      if (state.ctab === 'stats') loadStats();
      else updateChrome();
    },
    setVisible(visible) {
      if (state.visible === visible) return;
      state.visible = visible;
      if (visible) {
        if (state.sid) {
          loadSessions().then(() => openWS());
        }
      } else {
        closeWS();
      }
    },
  };
})();
