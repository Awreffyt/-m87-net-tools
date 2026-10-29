/* 站点探测 */
(function () {
  'use strict';

  const NS = window.NS;
  const $ = NS.$;
  const esc = NS.esc;

  const el = {};
  let current = null;
  let running = false;

  function grab() {
    el.input = $('#probeInput');
    el.btn = $('#probeBtn');
    el.clear = $('#probeClear');
    el.batchBtn = $('#probeBatchBtn');
    el.batchBox = $('#probeBatchBox');
    el.batchInput = $('#probeBatchInput');
    el.batchRun = $('#probeBatchRun');
    el.batchClose = $('#probeBatchClose');
    el.batchResults = $('#probeBatchResults');
    el.error = $('#probeError');
    el.empty = $('#probeEmpty');
    el.loading = $('#probeLoading');
    el.result = $('#probeResult');
    el.score = $('#probeScore');
    el.favicon = $('#probeFavicon');
    el.target = $('#probeTarget');
    el.grade = $('#probeGrade');
    el.chips = $('#probeChips');
    el.meta = $('#probeMeta');
    el.reprobe = $('#probeReprobe');
    el.copy = $('#probeCopy');
    el.export = $('#probeExport');
    el.dnsCard = $('#probeDnsCard');
    el.tlsCard = $('#probeTlsCard');
    el.endpoints = $('#probeEndpoints');
    el.security = $('#probeSecurityCard');
    el.hints = $('#probeHintsCard');
    el.examples = $('#probeExamples');
  }

  function setError(message) {
    if (!el.error) return;
    if (!message) {
      el.error.classList.add('hidden');
      el.error.textContent = '';
      return;
    }
    el.error.textContent = message;
    el.error.classList.remove('hidden');
  }

  function show(state) {
    el.empty.classList.toggle('hidden', state !== 'empty');
    el.loading.classList.toggle('hidden', state !== 'loading');
    el.result.classList.toggle('hidden', state !== 'result');
  }

  function badge(text, tone) {
    return `<span class="badge ${tone || ''}">${esc(text)}</span>`;
  }

  function kv(rows) {
    const body = rows.map(([k, v, muted]) =>
      `<div class="k">${esc(k)}</div><div class="v${muted ? ' muted' : ''}">${v}</div>`).join('');
    return `<div class="kv">${body}</div>`;
  }

  function renderScore(score) {
    const value = Math.max(0, Math.min(100, Number(score) || 0));
    let ring = 'var(--red)';
    if (value >= 75) ring = 'var(--green)';
    else if (value >= 55) ring = 'var(--amber)';
    el.score.style.setProperty('--score', value);
    el.score.style.setProperty('--ring', ring);
    el.score.innerHTML = `<b>${value}</b>`;
  }

  function toneForScore(score) {
    if (score >= 75) return 'green';
    if (score >= 55) return 'amber';
    return 'red';
  }

  function renderResult(data) {
    current = data;
    const summary = data.summary || {};
    const dns = data.dns || {};
    const tls = data.tls || {};
    const security = data.security || { items: [], passed: 0, total: 0 };

    renderScore(summary.score);

    const host = data.target || '-';
    el.target.textContent = host;
    el.grade.textContent = summary.grade || '-';
    el.grade.className = `badge ${toneForScore(summary.score || 0)}`;

    if (el.favicon) el.favicon.classList.add('hidden');

    const chips = [];
    chips.push(badge(summary.httpsSupported ? 'HTTPS 可用' : 'HTTPS 不可用', summary.httpsSupported ? 'green' : 'red'));
    chips.push(badge(summary.httpSupported ? 'HTTP 可用' : 'HTTP 关闭', summary.httpSupported ? 'blue' : ''));
    if (summary.isHtmlSite) chips.push(badge('HTML 站点', 'purple'));
    const hops = (data.https && data.https.redirectChain) || (data.http && data.http.redirectChain) || [];
    if (hops.length) chips.push(badge(`跳转 ${hops.length} 次`, 'blue'));
    if (tls.available) {
      chips.push(badge(`TLS ${tls.daysLeft} 天`, tls.daysLeft < 0 ? 'red' : tls.daysLeft < 21 ? 'amber' : 'green'));
    }
    if (summary.server) chips.push(badge(summary.server));
    el.chips.innerHTML = chips.join('');

    const finalUrl = summary.finalUrl || data.normalized || '';
    el.meta.textContent = `${data.normalized || ''}${finalUrl && finalUrl !== data.normalized ? '  跳转到  ' + finalUrl : ''}`;

    /* DNS */
    const dnsRows = [];
    if (dns.ipv4 && dns.ipv4.length) dnsRows.push(['IPv4', dns.ipv4.map(esc).join('<br>')]);
    if (dns.ipv6 && dns.ipv6.length) dnsRows.push(['IPv6', dns.ipv6.map(esc).join('<br>')]);
    dnsRows.push(['解析耗时', `${dns.latency || 0} ms`]);
    dnsRows.push(['地址数量', `${(dns.ips || []).length}`]);
    el.dnsCard.innerHTML = `<div class="card-title">DNS 解析<span class="right">${esc(data.target || '')}</span></div>${
      dns.resolved ? kv(dnsRows) : '<div style="font-size:12px;color:#fca5a5">域名解析失败</div>'}`;

    /* TLS */
    if (tls.available) {
      const sanText = (tls.san || []).map(esc).join('<br>') || '-';
      el.tlsCard.innerHTML = `<div class="card-title">TLS 证书<span class="right">${esc(tls.version || '')}</span></div>${
        kv([
          ['签发机构', esc(tls.issuer || '-')],
          ['证书主体', esc(tls.subject || '-')],
          ['生效时间', esc(tls.validFrom || '-')],
          ['到期时间', esc(tls.validTo || '-')],
          ['剩余天数', `<span style="color:${tls.daysLeft < 0 ? '#fca5a5' : tls.daysLeft < 21 ? '#fcd34d' : '#6ee7b7'}">${tls.daysLeft}</span>`],
          ['加密套件', esc(tls.cipher || '-')],
          ['SAN 数量', `${tls.sanCount || 0}`],
          ['域名列表', sanText],
          ['自签名', tls.selfSigned ? '是' : '否'],
        ])}`;
    } else {
      el.tlsCard.innerHTML = `<div class="card-title">TLS 证书</div>
        <div style="font-size:12px;color:var(--muted);line-height:1.6">${esc(tls.error || '未获取到证书信息')}</div>`;
    }

    /* 端点 */
    const endpointHtml = [renderEndpoint('HTTP', data.http), renderEndpoint('HTTPS', data.https)].join('');
    el.endpoints.innerHTML = `<div class="card-title">端点连通性</div>${endpointHtml}`;

    /* 安全响应头 */
    const audit = security.unavailable
      ? `<div style="font-size:12px;color:var(--muted);line-height:1.6">${
        esc(security.note || '当前环境无法读取跨域响应头，此项需后端服务')}</div>`
      : security.items.map((item) => `
      <div class="audit-row">
        <span class="ind ${item.present ? 'ok' : 'no'}"></span>
        <span class="label">${esc(item.label)}</span>
        <span class="value ${item.present ? 'ok' : ''}" title="${esc(item.value || '')}">${
          item.present ? esc(item.value || '已配置') : '缺失'}</span>
      </div>`).join('');
    el.security.innerHTML = `<div class="card-title">安全响应头
      <span class="right">${security.unavailable ? '不可用' : `${security.passed || 0} / ${security.total || 0} 已配置`}</span></div>
      ${security.unavailable ? audit : `<div class="audit-list">${audit}</div>`}`;

    /* 建议 */
    const hints = (data.hints || []).slice();
    const missingMinor = security.unavailable ? [] : security.items
      .filter((item) => !item.present && ['low', 'mid'].includes(item.level))
      .map((item) => item.label);
    if (!hints.length && missingMinor.length) {
      hints.push(`还有 ${missingMinor.length} 项次要响应头未配置：${missingMinor.join('、')}，可按需补充。`);
    }
    el.hints.innerHTML = `<div class="card-title">整改建议</div>${
      hints.length
        ? `<div class="hint-list">${hints.map((h) => `<div class="hint-item"><span class="ic">◆</span><span>${esc(h)}</span></div>`).join('')}</div>`
        : '<div style="font-size:12px;color:#6ee7b7">未发现明显问题，配置良好。</div>'}`;

    show('result');
  }

  function renderEndpoint(name, result) {
    if (!result) {
      return `<div class="endpoint-card"><div class="endpoint-head"><span class="name">${name}</span>
        <span class="spacer"></span>${badge('未检测', '')}</div></div>`;
    }
    const ok = !!result.open;
    const head = `<div class="endpoint-head">
      <span class="name">${name}</span>
      ${badge(ok ? `HTTP ${result.status}` : (result.error || '连接失败'), ok ? 'green' : 'red')}
      <span class="spacer"></span>
      <span style="font-size:10.5px;color:var(--dim);font-family:var(--mono)">${esc(result.finalUrl || '')}</span>
    </div>`;
    const stats = `<div class="stat-row">
      <div class="stat-item"><div class="label">状态码</div><div class="value">${result.status || '-'}</div></div>
      <div class="stat-item"><div class="label">耗时</div><div class="value">${result.latency || 0} ms</div></div>
      <div class="stat-item"><div class="label">大小</div><div class="value">${NS.fmtBytes(result.size || 0)}</div></div>
      <div class="stat-item"><div class="label">跳转</div><div class="value">${(result.redirectChain || []).length}</div></div>
      <div class="stat-item"><div class="label">类型</div><div class="value" style="font-size:11px">${esc((result.contentType || '-').split(';')[0])}</div></div>
    </div>`;
    const chain = result.redirectChain || [];
    const chainHtml = chain.length
      ? `<div class="redirect-chain">${chain.map((hop) =>
        `<div class="redirect-hop"><span class="code">${hop.status}</span><span>${esc(hop.to)}</span></div>`).join('')}</div>`
      : '';
    const errorHtml = result.error
      ? `<div style="font-size:11.5px;color:#fca5a5;margin-top:6px">${esc(result.error)}</div>` : '';
    return `<div class="endpoint-card">${head}${stats}${chainHtml}${errorHtml}</div>`;
  }

  function reportText(data) {
    const summary = data.summary || {};
    const lines = [
      `站点探测报告：${data.target}`,
      `时间：${new Date(data.timestamp).toLocaleString()}`,
      `地址：${data.normalized}`,
      `评分：${summary.score}/100（${summary.grade}）`,
      `HTTPS：${summary.httpsSupported ? '可用' : '不可用'}    HTTP：${summary.httpSupported ? '可用' : '不可用'}`,
      `首选协议：${summary.preferredProtocol}`,
      '',
      `DNS：${(data.dns && data.dns.ips || []).join(', ') || '解析失败'}`,
    ];
    if (data.tls && data.tls.available) {
      lines.push(`TLS：${data.tls.issuer}，${data.tls.version}，剩余 ${data.tls.daysLeft} 天`);
    }
    const security = data.security || { items: [] };
    lines.push('', `安全响应头：${security.passed}/${security.total}`);
    security.items.forEach((item) => {
      lines.push(`  ${item.present ? '✓' : '✗'} ${item.label}${item.present ? `：${item.value}` : ''}`);
    });
    if ((data.hints || []).length) {
      lines.push('', '整改建议：');
      data.hints.forEach((hint) => lines.push(`  - ${hint}`));
    }
    return lines.join('\n');
  }

  async function run(urlOverride) {
    if (running) return;
    const url = (urlOverride !== undefined ? urlOverride : el.input.value || '').trim();
    if (!url) {
      setError('请输入要探测的域名或网址');
      el.input.focus();
      return;
    }
    if (urlOverride !== undefined) el.input.value = url;
    running = true;
    setError('');
    show('loading');
    NS.setLoading(el.btn, true, '探测中...');
    try {
      const data = await NS.api(`/api/tools/probe?${NS.qs({ url })}`);
      renderResult(data);
    } catch (err) {
      show('empty');
      setError(err.message || '探测失败');
    } finally {
      running = false;
      NS.setLoading(el.btn, false);
    }
  }

  function batchRow(item) {
    if (item.error) {
      return `<div class="res-row">
        <div class="txt"><div class="name">${esc(item.input || '-')}</div>
        <div class="url" style="color:#fca5a5">${esc(item.error)}</div></div>
        <span class="badge red">失败</span>
      </div>`;
    }
    const summary = item.summary || {};
    const tls = item.tls || {};
    return `<div class="res-row">
      <div class="txt">
        <div class="name">${esc(item.target || item.input || '-')}</div>
        <div class="url">${esc(summary.finalUrl || item.normalized || '')}</div>
      </div>
      <span class="badge ${toneForScore(summary.score || 0)}">${summary.score || 0} 分，${esc(summary.grade || '')}</span>
      <span class="badge ${summary.httpsSupported ? 'green' : 'red'}">${summary.httpsSupported ? 'HTTPS' : 'HTTP'}</span>
      <span class="badge ${tls.available && tls.daysLeft >= 21 ? 'blue' : tls.available ? 'amber' : ''}">${
        tls.available ? `${tls.daysLeft} 天` : '无证书'}</span>
    </div>`;
  }

  async function runBatch() {
    const urls = (el.batchInput.value || '').split(/\r?\n/).map((v) => v.trim()).filter(Boolean);
    if (!urls.length) {
      NS.toast('请至少输入一个网址', true);
      return;
    }
    if (urls.length > 12) {
      NS.toast('一次最多 12 个网址', true);
      return;
    }
    NS.setLoading(el.batchRun, true, '批量探测中...');
    el.batchResults.innerHTML = '<div class="loading-state"><div class="skel" style="height:70px"></div><div class="skel" style="height:70px"></div></div>';
    try {
      const data = await NS.api('/api/tools/probe-batch', { method: 'POST', body: { urls } });
      const results = data.results || [];
      el.batchResults.innerHTML = `<div class="card" style="margin-top:12px">
        <div class="card-title">批量结果<span class="right">${results.length} 个站点</span></div>
        <div class="res-row-list">${results.map(batchRow).join('')}</div>
      </div>`;
    } catch (err) {
      el.batchResults.innerHTML = `<div class="alert" style="margin-top:12px">${esc(err.message)}</div>`;
    } finally {
      NS.setLoading(el.batchRun, false);
    }
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
    if (el.examples) {
      el.examples.addEventListener('click', (event) => {
        const chip = event.target.closest('.chip');
        if (!chip) return;
        el.input.value = chip.dataset.url || '';
        run();
      });
    }
    el.batchBtn.addEventListener('click', () => {
      el.batchBox.classList.toggle('hidden');
      if (!el.batchBox.classList.contains('hidden')) el.batchInput.focus();
    });
    el.batchClose.addEventListener('click', () => el.batchBox.classList.add('hidden'));
    el.batchRun.addEventListener('click', runBatch);
    el.reprobe.addEventListener('click', () => run());
    el.copy.addEventListener('click', async () => {
      if (!current) return;
      const ok = await NS.copyText(reportText(current));
      NS.toast(ok ? '报告已复制到剪贴板' : '复制失败，请手动选择', !ok);
    });
    el.export.addEventListener('click', () => {
      if (!current) return;
      NS.downloadText(JSON.stringify(current, null, 2), `probe-${current.target}.json`, 'application/json;charset=utf-8');
    });
  }

  NS.probe = {
    init() {
      grab();
      bind();
    },
  };
})();
