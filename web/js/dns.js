/* DNS 查询 */
(function () {
  'use strict';

  const NS = window.NS;
  const $ = NS.$;
  const esc = NS.esc;

  const RESOLVERS = [
    { key: 'alidns', label: '阿里 DNS' },
    { key: 'cloudflare', label: 'Cloudflare' },
    { key: 'google', label: 'Google' },
  ];

  const el = {};
  const state = { data: null, type: 'ALL', resolver: 'alidns', filter: 'ALL' };
  let running = false;

  function grab() {
    el.input = $('#dnsInput');
    el.btn = $('#dnsBtn');
    el.clear = $('#dnsClear');
    el.typeChips = $('#dnsTypeChips');
    el.resolver = $('#dnsResolver');
    el.examples = $('#dnsExamples');
    el.error = $('#dnsError');
    el.empty = $('#dnsEmpty');
    el.loading = $('#dnsLoading');
    el.result = $('#dnsResult');
    el.total = $('#dnsTotal');
    el.types = $('#dnsTypes');
    el.resolverLabel = $('#dnsResolverLabel');
    el.queryMs = $('#dnsQueryMs');
    el.recordMeta = $('#dnsRecordMeta');
    el.recordFilter = $('#dnsRecordFilter');
    el.records = $('#dnsRecords');
    el.noRecords = $('#dnsNoRecords');
    el.propBtn = $('#dnsPropBtn');
    el.propList = $('#dnsPropList');
    el.copy = $('#dnsCopy');
    el.json = $('#dnsJson');
    el.csv = $('#dnsCsv');
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

  function typeTag(type) {
    return `<span class="type-tag type-${esc(type)}">${esc(type)}</span>`;
  }

  function rowsForFilter() {
    if (!state.data) return [];
    const records = state.data.records || [];
    return state.filter === 'ALL' ? records : records.filter((rec) => rec.type === state.filter);
  }

  function renderFilterChips() {
    if (!state.data) return;
    const types = state.data.summary && state.data.summary.types || [];
    const chips = [`<button class="chip ${state.filter === 'ALL' ? 'active' : ''}" data-type="ALL">全部</button>`];
    types.forEach((type) => {
      chips.push(`<button class="chip ${state.filter === type ? 'active' : ''}" data-type="${esc(type)}">${esc(type)}</button>`);
    });
    el.recordFilter.innerHTML = chips.join('');
    el.noRecords.classList.toggle('hidden', rowsForFilter().length !== 0);
  }

  function renderRecords() {
    const rows = rowsForFilter();
    el.records.innerHTML = rows.map((rec) => `
      <tr>
        <td>${typeTag(rec.type)}</td>
        <td class="mono">${esc(rec.name)}</td>
        <td class="ttl">${rec.ttl || '-'}</td>
        <td class="mono">${esc(rec.data)}</td>
        <td><button class="chip" data-copy="${esc(rec.data)}" style="padding:2px 8px;font-size:10px">复制</button></td>
      </tr>`).join('');
    el.noRecords.classList.toggle('hidden', rows.length !== 0);
    el.recordMeta.textContent = `${rows.length} / ${(state.data.records || []).length} 条`;
  }

  function render() {
    const data = state.data;
    el.total.textContent = data.summary.total;
    el.types.textContent = (data.summary.types || []).join(' / ') || '-';
    el.resolverLabel.textContent = data.resolverLabel || data.resolver;
    el.queryMs.innerHTML = `${data.queryMs}<small style="font-size:10px;color:var(--dim)">ms</small>`;
    state.filter = 'ALL';
    renderFilterChips();
    renderRecords();
    el.propList.innerHTML = `<div style="font-size:11.5px;color:var(--dim);line-height:1.6">点击「开始对比」，将同时向阿里 DNS、Cloudflare、Google 查询当前域名，检查解析结果是否一致。</div>`;
    show('result');
    if (data.errors && data.errors.length) setError(data.errors.join('；'));
    else setError('');
  }

  async function run(target) {
    if (running) return;
    const value = (target !== undefined ? target : el.input.value || '').trim();
    if (!value) {
      setError('请输入域名或 IP');
      el.input.focus();
      return;
    }
    if (target !== undefined) el.input.value = value;
    running = true;
    setError('');
    show('loading');
    NS.setLoading(el.btn, true, '查询中...');
    try {
      const data = await NS.api(`/api/tools/dns?${NS.qs({ url: value, type: state.type, resolver: state.resolver })}`);
      state.data = data;
      render();
    } catch (err) {
      show('empty');
      setError(err.message || '查询失败');
    } finally {
      running = false;
      NS.setLoading(el.btn, false);
    }
  }

  function ipList(records) {
    const v4 = records.filter((r) => r.type === 'A').map((r) => r.data);
    const v6 = records.filter((r) => r.type === 'AAAA').map((r) => r.data);
    const other = records.filter((r) => r.type === 'CNAME').map((r) => r.data);
    const parts = [];
    if (v4.length) parts.push(`v4 ${v4.join(', ')}`);
    if (v6.length) parts.push(`v6 ${v6.join(', ')}`);
    if (other.length) parts.push(`CNAME ${other.join(', ')}`);
    return parts.join('，') || '无记录';
  }

  async function compare() {
    if (!state.data) return;
    const domain = state.data.domain;
    const isIp = /^[0-9.]+$/.test(domain) || domain.includes(':');
    const types = isIp ? ['PTR'] : ['A', 'AAAA'];
    NS.setLoading(el.propBtn, true, '对比中...');
    el.propList.innerHTML = `<div style="font-size:11.5px;color:var(--dim)">正在向 3 个解析器查询...</div>`;
    try {
      const tasks = RESOLVERS.map(async (resolver) => {
        try {
          const chunks = await Promise.all(types.map((type) =>
            NS.api(`/api/tools/dns?${NS.qs({ url: domain, type, resolver: resolver.key })}`)));
          const records = chunks.flatMap((chunk) => chunk.records || []);
          return { resolver, records, error: null };
        } catch (err) {
          return { resolver, records: [], error: err.message || '查询失败' };
        }
      });
      const results = await Promise.all(tasks);
      const okSets = results.filter((item) => !item.error).map((item) =>
        Array.from(new Set(item.records.map((rec) => `${rec.type}|${rec.data}`))).sort().join('\n'));
      const consistent = okSets.length > 1 && okSets.every((s) => s === okSets[0]) && okSets[0] !== '';
      el.propList.innerHTML = results.map((item) => {
        let badge = '<span class="badge red">失败</span>';
        if (!item.error) {
          if (okSets.length < 2) badge = '<span class="badge">仅 1 个可用</span>';
          else badge = consistent ? '<span class="badge green">一致</span>' : '<span class="badge amber">不一致</span>';
        }
        return `<div class="prop-row">
          <span class="name">${esc(item.resolver.label)}</span>
          <span class="ips">${item.error ? esc(item.error) : esc(ipList(item.records))}</span>
          <span class="state">${badge}</span>
        </div>`;
      }).join('');
      if (okSets.length > 1) {
        el.propList.insertAdjacentHTML('beforeend', `<div style="font-size:11px;color:${
          consistent ? '#6ee7b7' : '#fcd34d'};padding:4px 2px">${
          consistent ? '三个解析器返回结果完全一致。' : '解析结果存在差异，可能处于 DNS 生效中或存在地域调度。'}</div>`);
      }
    } catch (err) {
      el.propList.innerHTML = `<div class="alert">${esc(err.message || '对比失败')}</div>`;
    } finally {
      NS.setLoading(el.propBtn, false);
    }
  }

  function reportText() {
    const data = state.data;
    if (!data) return '';
    const lines = [
      `DNS 查询：${data.domain}`,
      `解析器：${data.resolverLabel}    类型：${data.type}    耗时：${data.queryMs}ms`,
      `记录数：${data.records.length}`,
      '',
    ];
    data.records.forEach((rec) => lines.push(`${rec.type}\t${rec.name}\t${rec.ttl}\t${rec.data}`));
    return lines.join('\n');
  }

  function bind() {
    el.btn.addEventListener('click', () => run());
    el.input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') run();
    });
    el.clear.addEventListener('click', () => {
      el.input.value = '';
      el.input.focus();
      setError('');
      show('empty');
    });
    el.typeChips.addEventListener('click', (event) => {
      const chip = event.target.closest('.chip');
      if (!chip) return;
      state.type = chip.dataset.type;
      NS.$$('.chip', el.typeChips).forEach((node) => node.classList.toggle('active', node === chip));
      if ((el.input.value || '').trim()) run();
    });
    el.resolver.addEventListener('change', () => {
      state.resolver = el.resolver.value;
      if ((el.input.value || '').trim()) run();
    });
    if (el.examples) {
      el.examples.addEventListener('click', (event) => {
        const chip = event.target.closest('.chip');
        if (!chip) return;
        el.input.value = chip.dataset.url || '';
        run();
      });
    }
    el.recordFilter.addEventListener('click', (event) => {
      const chip = event.target.closest('.chip');
      if (!chip) return;
      state.filter = chip.dataset.type;
      renderFilterChips();
      renderRecords();
    });
    el.records.addEventListener('click', async (event) => {
      const button = event.target.closest('button[data-copy]');
      if (!button) return;
      const ok = await NS.copyText(button.dataset.copy);
      NS.toast(ok ? '已复制' : '复制失败', !ok);
    });
    el.propBtn.addEventListener('click', compare);
    el.copy.addEventListener('click', async () => {
      const ok = await NS.copyText(reportText());
      NS.toast(ok ? '结果已复制' : '复制失败', !ok);
    });
    el.json.addEventListener('click', () => {
      if (!state.data) return;
      NS.downloadText(JSON.stringify(state.data, null, 2), `dns-${state.data.domain}.json`, 'application/json;charset=utf-8');
    });
    el.csv.addEventListener('click', () => {
      if (!state.data) return;
      const rows = [['类型', '名称', 'TTL', '数据']];
      state.data.records.forEach((rec) => rows.push([rec.type, rec.name, rec.ttl, rec.data]));
      NS.downloadText('\ufeff' + NS.csv(rows), `dns-${state.data.domain}.csv`, 'text/csv;charset=utf-8');
    });
  }

  NS.dns = {
    init() {
      grab();
      bind();
    },
  };
})();
