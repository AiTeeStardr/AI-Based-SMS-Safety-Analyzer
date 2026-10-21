/* SMS Guard AI — shared UI: icons, header/footer, history store, render helpers */
(function (global) {
  const SG = global.SG = global.SG || {};
  SG.BASE_SCORE = 15;

  /* ---------- Icons (inline sprite) ---------- */
  const ICONS = {
    'shield': '<path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/>',
    'shield-check': '<path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/>',
    'shield-alert': '<path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/><path d="M12 8v5M12 16v.5"/>',
    'message': '<path d="M4 5h16v11H9l-5 4V5z"/><path d="M8 9h8M8 12h5"/>',
    'image': '<rect x="4" y="5" width="16" height="14" rx="2"/><circle cx="9" cy="10" r="1.5"/><path d="M4 17l5-5 4 4 3-3 4 4"/>',
    'chart': '<path d="M5 20V11M11 20V4M17 20v-6M3 20h18"/>',
    'cpu': '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 9h6v6H9zM9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
    'clock': '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    'search': '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
    'copy': '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 012-2h9"/>',
    'phone': '<path d="M5 4h4l2 5-2.5 1.5a11 11 0 005 5L15 13l5 2v4a1 1 0 01-1 1A16 16 0 014 5a1 1 0 011-1z"/>',
    'check': '<path d="M5 12l5 5 9-10"/>',
    'alert': '<path d="M12 3l10 18H2L12 3z"/><path d="M12 10v5M12 18v.5"/>',
    'arrow-right': '<path d="M5 12h14M13 6l6 6-6 6"/>',
    'upload': '<path d="M12 16V4M7 9l5-5 5 5M4 20h16"/>',
    'menu': '<path d="M4 7h16M4 12h16M4 17h16"/>',
    'close': '<path d="M6 6l12 12M18 6L6 18"/>',
    'home': '<path d="M4 11l8-7 8 7M6 10v10h12V10"/>',
    'trash': '<path d="M5 7h14M9 7V4h6v3M7 7l1 13h8l1-13"/>',
    'chevron-right': '<path d="M9 6l6 6-6 6"/>',
    'chevron-left': '<path d="M15 6l-6 6 6 6"/>',
    'info': '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8v.5"/>',
    'lock': '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
    'share': '<circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M8.2 10.8l7.6-3.6M8.2 13.2l7.6 3.6"/>',
    'plus': '<path d="M12 5v14M5 12h14"/>'
  };
  function icon(name, cls) {
    return `<svg class="ic ${cls || ''}" aria-hidden="true" viewBox="0 0 24 24">${ICONS[name] || ''}</svg>`;
  }
  SG.icon = icon;

  const BRAND_MARK = `<svg class="brand-mark" viewBox="0 0 40 40" aria-hidden="true"><path d="M20 3l14 5.5v10c0 9-6 16.5-14 19-8-2.5-14-10-14-19v-10L20 3z" fill="#E5384F"/><path d="M13.5 20.5l5 5 9-10" fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

  /* ---------- Utils ---------- */
  SG.escapeHtml = function (s) {
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  };
  SG.fmtDate = function (ts) {
    return new Date(ts).toLocaleString('th-TH', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  };
  SG.toast = function (msg) {
    const t = document.createElement('div');
    t.className = 'toast'; t.setAttribute('role', 'status'); t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2800);
  };
  SG.levelText = { danger: 'ไม่น่าเชื่อถือ', safe: 'น่าเชื่อถือ' };
  SG.THRESHOLD = 50;
  // ประวัติเก่าอาจมีระดับ 'warn' (เวอร์ชัน 3 ระดับ) — แปลงเป็นสองคลาสตามคะแนน
  SG.normLevel = r => (r.percent >= SG.THRESHOLD ? 'danger' : 'safe');

  /* ---------- History store (localStorage, อยู่ในเบราว์เซอร์เครื่องนี้เท่านั้น) ---------- */
  const KEY = 'smsguard.history.v1';
  const MAX = 200;
  function read() { try { return JSON.parse(localStorage.getItem(KEY)) || []; } catch (e) { return []; } }
  function write(a) { try { localStorage.setItem(KEY, JSON.stringify(a)); return true; } catch (e) { return false; } }
  SG.history = {
    all: read,
    add(result, source) {
      const rec = Object.assign({ id: Date.now().toString(36) + Math.random().toString(36).slice(2, 5), ts: Date.now(), source: source || 'text' }, result);
      const list = read(); list.unshift(rec); write(list.slice(0, MAX));
      return rec;
    },
    get(id) { return read().find(r => r.id === id) || null; },
    clear() { write([]); }
  };
  /* ---------- Python backend (server.py) — ถ้าติดต่อไม่ได้คืน null แล้วเว็บใช้เฉพาะระบบกฎ ---------- */
  SG.api = {
    async analyze(text) {
      const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 8000);
      try {
        const res = await fetch('api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }), signal: ctl.signal });
        if (!res.ok) return null;
        const j = await res.json();
        return typeof j.scam_probability === 'number' ? j : null;
      } catch (e) { return null; } finally { clearTimeout(timer); }
    }
  };
  SG.pref = {
    get(k) { try { return localStorage.getItem('smsguard.' + k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem('smsguard.' + k, v); } catch (e) {} }
  };

  /* ---------- Result renderers (ใช้ในหน้าผลวิเคราะห์) ---------- */
  SG.renderAnnotated = function (text, ranges) {
    const esc = SG.escapeHtml;
    const sorted = (ranges || []).slice().sort((a, b) => a[0] - b[0] || (a[2] === 'danger' ? -1 : 1));
    const merged = [];
    sorted.forEach(r => {
      const last = merged[merged.length - 1];
      if (last && r[0] < last[1]) { last[1] = Math.max(last[1], r[1]); if (r[2] === 'danger') last[2] = 'danger'; }
      else merged.push(r.slice());
    });
    let html = '', pos = 0;
    merged.forEach(([s, e, t]) => { html += esc(text.slice(pos, s)) + `<mark class="m-${t}">` + esc(text.slice(s, e)) + '</mark>'; pos = e; });
    return html + esc(text.slice(pos));
  };

  SG.renderWaterfall = function (el, percent, contrib) {
    const clamp = v => Math.min(100, Math.max(0, v));
    const rows = [{ kind: 'base', label: 'ค่าเริ่มต้น', from: 0, to: SG.BASE_SCORE, text: String(SG.BASE_SCORE) }];
    let cum = SG.BASE_SCORE;
    contrib.forEach(c => {
      const a = clamp(cum), b = clamp(cum + c.score);
      rows.push({ kind: c.score > 0 ? 'up' : 'down', label: c.label, from: Math.min(a, b), to: Math.max(a, b), text: (c.score > 0 ? '+' : '−') + Math.abs(c.score) });
      cum += c.score;
    });
    const adj = percent - cum;
    if (Math.abs(adj) >= 1) {
      const a = clamp(cum);
      rows.push({ kind: 'adj', label: 'ปรับตามบริบทและลิงก์', from: Math.min(a, percent), to: Math.max(a, percent), text: (adj > 0 ? '+' : '−') + Math.abs(Math.round(adj)) });
    }
    rows.push({ kind: 'total', label: 'รวม', from: 0, to: percent, text: percent + '%' });
    el.innerHTML = rows.map(r => `
      <div class="wf-row ${r.kind === 'total' ? 'total' : ''}">
        <div class="wf-label">${SG.escapeHtml(r.label)}</div>
        <div class="wf-track"><div class="wf-bar ${r.kind}" data-w="${r.to - r.from}" style="left:${r.from}%"></div></div>
        <div class="wf-val">${r.text}</div>
      </div>`).join('');
    requestAnimationFrame(() => requestAnimationFrame(() => {
      el.querySelectorAll('.wf-bar').forEach(b => { b.style.width = b.dataset.w + '%'; });
    }));
  };

  SG.renderGauge = function (el, percent) {
    const r = 52, c = 2 * Math.PI * r;
    el.innerHTML = `<svg viewBox="0 0 132 132" role="img" aria-label="ระดับความเสี่ยง ${percent} จาก 100">
      <circle cx="66" cy="66" r="${r}" fill="none" stroke="var(--line)" stroke-width="12"/>
      <circle class="arc" cx="66" cy="66" r="${r}" fill="none" stroke="var(--level)" stroke-width="12" stroke-linecap="round"
        stroke-dasharray="${c}" stroke-dashoffset="${c}" transform="rotate(-90 66 66)" data-off="${c * (1 - percent / 100)}"/>
      <text class="num" x="66" y="70" text-anchor="middle">${percent}</text>
      <text class="den" x="66" y="90" text-anchor="middle">/100</text></svg><small>ระดับความเสี่ยง</small>`;
    requestAnimationFrame(() => requestAnimationFrame(() => {
      const arc = el.querySelector('.arc'); arc.style.strokeDashoffset = arc.dataset.off;
    }));
  };

  /* ---------- Header / Footer ---------- */
  const NAV = [
    ['home', 'index.html', 'หน้าแรก', 'home'],
    ['check', 'check.html', 'ตรวจสอบ SMS', 'message'],
    ['history', 'history.html', 'ประวัติการตรวจสอบ', 'clock'],
    ['model', 'model.html', 'ข้อมูลโมเดล', 'cpu'],
    ['examples', 'examples.html', 'ข้อมูลทดสอบ', 'check']
  ];

  SG.mount = function (active) {
    // นับ "result" เป็นส่วนของเมนูตรวจสอบ
    const cur = active === 'result' ? 'check' : active;
    const links = NAV.map(n => `<a href="${n[1]}" ${n[0] === cur ? 'aria-current="page"' : ''}>${n[2]}</a>`).join('');
    const mlinks = NAV.map(n => `<a href="${n[1]}" ${n[0] === cur ? 'aria-current="page"' : ''}>${icon(n[3])}${n[2]}</a>`).join('');
    const header = document.createElement('header');
    header.className = 'site-header';
    header.innerHTML = `
      <div class="wrap">
        <a class="brand" href="index.html" aria-label="SMS Guard AI หน้าแรก">${BRAND_MARK}<span><b>SMS Guard AI</b><small>AI-Based SMS Safety Analyzer</small></span></a>
        <nav class="nav" aria-label="เมนูหลัก">${links}</nav>
        <div class="header-tools">
          <button type="button" class="icon-btn font-btn" id="fontBtn" aria-pressed="false" aria-label="ขยายขนาดตัวอักษร" title="ขยายขนาดตัวอักษร">ก<sup>+</sup></button>
          <button type="button" class="icon-btn nav-toggle" id="navToggle" aria-expanded="false" aria-controls="mobileNav" aria-label="เปิดเมนู">${icon('menu')}</button>
        </div>
      </div>
      <nav class="mobile-nav hidden" id="mobileNav" aria-label="เมนูมือถือ">${mlinks}</nav>`;
    document.body.insertBefore(header, document.querySelector('main'));

    const footer = document.createElement('footer');
    footer.className = 'site-footer';
    footer.innerHTML = `
      <div class="wrap">
        <a class="brand" href="index.html" style="margin:0">${BRAND_MARK}<span><b>SMS Guard AI</b><small>AI-Based SMS Safety Analyzer</small></span></a>
        <div class="footer-links"><a href="index.html">หน้าแรก</a><a href="check.html">ตรวจสอบ SMS</a><a href="history.html">ประวัติ</a><a href="model.html">ข้อมูลโมเดล</a><a href="examples.html">ข้อมูลทดสอบ</a><a href="tel:1441">โทร 1441</a></div>
        <p>โครงงานวิศวกรรมปัญญาประดิษฐ์ EN-AI-2569-1 · ผลการตรวจเป็นการประเมินจากกฎและรายชื่อโดเมนที่ระบบรู้จัก ไม่ใช่การรับรอง</p>
      </div>`;
    document.body.appendChild(footer);

    const toggle = document.getElementById('navToggle'), mnav = document.getElementById('mobileNav');
    toggle.addEventListener('click', () => {
      const open = mnav.classList.toggle('hidden') === false;
      toggle.setAttribute('aria-expanded', String(open));
      toggle.innerHTML = icon(open ? 'close' : 'menu');
    });

    const fontBtn = document.getElementById('fontBtn');
    function applyFont(on) {
      document.documentElement.classList.toggle('elderly', on);
      fontBtn.setAttribute('aria-pressed', String(on));
      fontBtn.setAttribute('aria-label', on ? 'ลดขนาดตัวอักษร' : 'ขยายขนาดตัวอักษร');
    }
    applyFont(SG.pref.get('elderly') === '1');
    fontBtn.addEventListener('click', () => {
      const on = !document.documentElement.classList.contains('elderly');
      applyFont(on); SG.pref.set('elderly', on ? '1' : '0');
    });
  };
})(window);
