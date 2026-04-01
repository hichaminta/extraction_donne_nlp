/* ============================================================
   CTI Shield – script.js
   ============================================================ */

// ── Global state ──────────────────────────────────────────
const PAGE_SIZE   = 50;

let G_allIocs     = [];   // full dataset
let G_filtered    = [];   // after search + type + tag filters
let G_page        = 0;    // current page index (0-based)
let G_activeType   = null; // e.g. "ip"
let G_activeSource = null; // e.g. "alienvault"
let G_query        = '';   // text search

let G_currentPageIocs = []; // IOCs on screen (for modal)
let G_visibleCves     = []; // CVEs on screen (for modal)
let G_allCves         = []; // full CVE dataset
let G_filteredCves    = []; // after search
let G_cvePage         = 0;    // current page index for CVEs

// Colour palettes
const TYPE_COLORS = {
    ip:      { bg: 'rgba(47,128,237,0.18)',  col: '#60a5fa' },
    url:     { bg: 'rgba(155,81,224,0.18)',  col: '#c084fc' },
    domain:  { bg: 'rgba(39,174,96,0.18)',   col: '#34d399' },
    sha256:  { bg: 'rgba(235,87,87,0.18)',   col: '#f87171' },
    sha1:    { bg: 'rgba(242,196,76,0.18)',  col: '#fbbf24' },
    md5:     { bg: 'rgba(242,153,74,0.18)',  col: '#fb923c' },
    email:   { bg: 'rgba(86,204,242,0.18)',  col: '#38bdf8' },
    unknown: { bg: 'rgba(100,116,139,0.18)', col: '#94a3b8' },
};
function typeColor(t) { return TYPE_COLORS[t] || TYPE_COLORS.unknown; }

const TAG_PALETTE = [
    { bg: 'rgba(155,81,224,0.18)',  col: '#c084fc' },
    { bg: 'rgba(47,128,237,0.18)',  col: '#60a5fa' },
    { bg: 'rgba(235,87,87,0.18)',   col: '#f87171' },
    { bg: 'rgba(242,196,76,0.18)', col: '#fbbf24' },
    { bg: 'rgba(39,174,96,0.18)',   col: '#34d399' },
    { bg: 'rgba(86,204,242,0.18)',  col: '#38bdf8' },
    { bg: 'rgba(242,153,74,0.18)', col: '#fb923c' },
    { bg: 'rgba(236,72,153,0.18)', col: '#f472b6' },
];
const tagColor = (i) => TAG_PALETTE[i % TAG_PALETTE.length];

/* ============================================================
   BOOT
   ============================================================ */
document.addEventListener('DOMContentLoaded', async () => {
    lucide.createIcons();
    const statusEl = document.getElementById('loading-status');
    const overlay  = document.getElementById('loading-overlay');

    try {
        statusEl.innerText = 'Fetching IOCs (320 MB)…';
        const iocRes = await fetch('/output_regex/iocs_extracted.json');
        if (!iocRes.ok) throw new Error('IOCs fetch failed');
        const iocs = await iocRes.json();

        statusEl.innerText = 'Fetching CVEs (230 MB)…';
        const cveRes = await fetch('/output_regex/cves_extracted.json');
        if (!cveRes.ok) throw new Error('CVEs fetch failed');
        const cves = await cveRes.json();

        statusEl.innerText = 'Building indexes…';
        window._cveIndex = Object.fromEntries(
            cves.filter(c => c.cve_id).map(c => [c.cve_id.toUpperCase(), c])
        );

        document.getElementById('total-iocs').innerText = iocs.length.toLocaleString();
        document.getElementById('total-cves').innerText = cves.length.toLocaleString();

        // Compute unique IOC sources
        const iocSourceSet = new Set();
        iocs.forEach(i => { if(Array.isArray(i.sources)) i.sources.forEach(s => s && iocSourceSet.add(s)); });
        document.getElementById('total-ioc-sources').innerText = iocSourceSet.size.toLocaleString();

        // Compute unique CVE sources
        const cveSourceSet = new Set();
        cves.forEach(c => { if(Array.isArray(c.sources)) c.sources.forEach(s => s && cveSourceSet.add(s)); });
        document.getElementById('total-cve-sources').innerText = cveSourceSet.size.toLocaleString();

        // Charts
        const typeCount = {};
        iocs.forEach(i => { const t = i.ioc_type || 'unknown'; typeCount[t] = (typeCount[t]||0)+1; });
        renderIOCDistribution(typeCount);
        renderTypeBreakdown(typeCount, iocs.length);

        const yearCount = {};
        cves.forEach(c => { const y = (c.cve_id||'').split('-')[1]||'?'; yearCount[y]=(yearCount[y]||0)+1; });
        renderCVETrend(yearCount);

        // Source charts
        renderSourcesChart('iocSourcesChart', iocSourceSet);
        renderSourcesChart('cveSourcesChart', cveSourceSet);

        // IOC section
        G_allIocs = iocs;
        buildTypeFilters(typeCount);
        buildSourceFilters(iocs);
        applyFilters();   // initial render

        // CVE section
        G_allCves = cves.reverse();
        applyCveFilters();

        document.getElementById('cveSearch').addEventListener('input', e => {
            G_cvePage = 0;
            applyCveFilters();
        });

        document.getElementById('iocSearch').addEventListener('input', e => {
            G_query = e.target.value.toLowerCase().trim();
            G_page  = 0;
            applyFilters();
        });

        setupNavigation();
        setupModals();

        overlay.style.opacity = '0';
        setTimeout(() => overlay.style.display = 'none', 500);

    } catch (err) {
        console.error(err);
        statusEl.innerHTML = `<span style="color:#f87171">Error: ${err.message}<br>Run start_dashboard.py first.</span>`;
    }
});

/* ============================================================
   CHARTS
   ============================================================ */
function renderIOCDistribution(typeCount) {
    new Chart(document.getElementById('iocDistributionChart'), {
        type: 'pie',
        data: {
            labels: Object.keys(typeCount),
            datasets: [{ data: Object.values(typeCount), borderWidth: 0,
                backgroundColor: ['#9b51e0','#2f80ed','#eb5757','#f2c94c','#27ae60','#56ccf2','#f2994a'] }]
        },
        options: { responsive: true, maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } } }
    });
}

function renderTypeBreakdown(typeCount, total) {
    const row = document.getElementById('typeBreakdownRow');
    if (!row) return;
    const entries = Object.entries(typeCount).sort((a,b) => b[1]-a[1]);
    row.innerHTML = entries.map(([type, count]) => {
        const c = typeColor(type);
        const pct = total > 0 ? ((count/total)*100).toFixed(1) : 0;
        return `<div class="type-mini-card" style="--tmc-bg:${c.bg};--tmc-col:${c.col}">
            <span class="tmc-type">${type}</span>
            <span class="tmc-count">${count.toLocaleString()}</span>
            <span class="tmc-pct">${pct}%</span>
            <div class="tmc-bar"><div class="tmc-fill" style="width:${pct}%;background:${c.col}"></div></div>
        </div>`;
    }).join('');
}

function renderSourcesChart(canvasId, sourceSet) {
    // skip — charts already wired via HTML, kept for future bar chart use
}

function renderCVETrend(yearCount) {
    const yrs = Object.keys(yearCount).sort();
    new Chart(document.getElementById('cveTrendChart'), {
        type: 'line',
        data: {
            labels: yrs,
            datasets: [{ label:'CVEs', data: yrs.map(y=>yearCount[y]),
                borderColor:'#2f80ed', backgroundColor:'rgba(47,128,237,0.1)',
                fill:true, tension:0.4 }]
        },
        options: { responsive:true, maintainAspectRatio:false,
            scales: { y:{grid:{color:'rgba(148,163,184,0.1)'},ticks:{color:'#94a3b8'}}, x:{ticks:{color:'#94a3b8'}} },
            plugins:{ legend:{display:false} } }
    });
}

/* ============================================================
   FILTER BARS
   ============================================================ */
function buildTypeFilters(typeCount) {
    const bar = document.getElementById('typeFilterBar');
    bar.innerHTML = '';

    const mkBtn = (label, type, c) => {
        const b = document.createElement('button');
        b.className   = 'flt-btn' + (type === null ? ' flt-active' : '');
        b.textContent = label;
        b.style.cssText = `--fb:${c.bg};--fc:${c.col}`;
        b.onclick = () => {
            document.querySelectorAll('#typeFilterBar .flt-btn').forEach(x => x.classList.remove('flt-active'));
            b.classList.add('flt-active');
            G_activeType = type;
            G_page = 0;
            applyFilters();
        };
        return b;
    };

    bar.appendChild(mkBtn('All Types', null, { bg:'rgba(248,250,252,0.08)', col:'#f8fafc' }));
    Object.keys(typeCount).sort().forEach(t => bar.appendChild(mkBtn(t, t, typeColor(t))));
}

function buildTagFilters(iocs) {
    const bar = document.getElementById('tagFilterBar');
    bar.innerHTML = '';

    // Collect unique non-null tags
    const tagSet = new Set();
    iocs.forEach(ioc => { if (Array.isArray(ioc.tags)) ioc.tags.forEach(t => t && tagSet.add(t)); });

    if (tagSet.size === 0) {
        bar.innerHTML = '<span class="no-tags-msg">Aucun tag dans les données</span>';
        return;
    }

    const mkBtn = (label, tag, c) => {
        const b = document.createElement('button');
        b.className   = 'flt-btn' + (tag === null ? ' flt-active' : '');
        b.textContent = label;
        b.style.cssText = `--fb:${c.bg};--fc:${c.col}`;
        b.dataset.tag = tag || '';
        b.onclick = () => {
            document.querySelectorAll('#tagFilterBar .flt-btn').forEach(x => x.classList.remove('flt-active'));
            b.classList.add('flt-active');
            G_activeTag = tag;
            G_page = 0;
            applyFilters();
        };
        return b;
    };

    bar.appendChild(mkBtn('All Tags', null, { bg:'rgba(248,250,252,0.08)', col:'#f8fafc' }));
    [...tagSet].sort().forEach((t, i) => bar.appendChild(mkBtn(t, t, tagColor(i))));
}

function buildSourceFilters(iocs) {
    const bar = document.getElementById('sourceFilterBar');
    if (!bar) return;
    bar.innerHTML = '';

    // Count occurrences per source
    const srcCount = {};
    iocs.forEach(ioc => {
        if (Array.isArray(ioc.sources)) ioc.sources.forEach(s => { if(s) srcCount[s] = (srcCount[s]||0)+1; });
    });

    if (Object.keys(srcCount).length === 0) {
        bar.innerHTML = '<span class="no-tags-msg">Aucune source dans les données</span>';
        return;
    }

    const SOURCE_PALETTE = [
        { bg:'rgba(96,165,250,0.18)',  col:'#60a5fa' },
        { bg:'rgba(52,211,153,0.18)',  col:'#34d399' },
        { bg:'rgba(251,146,60,0.18)',  col:'#fb923c' },
        { bg:'rgba(167,139,250,0.18)', col:'#a78bfa' },
        { bg:'rgba(244,114,182,0.18)', col:'#f472b6' },
        { bg:'rgba(56,189,248,0.18)',  col:'#38bdf8' },
        { bg:'rgba(251,191,36,0.18)',  col:'#fbbf24' },
        { bg:'rgba(248,113,113,0.18)', col:'#f87171' },
    ];
    const srcColor = i => SOURCE_PALETTE[i % SOURCE_PALETTE.length];

    const mkBtn = (label, src, c, badge) => {
        const b = document.createElement('button');
        b.className   = 'flt-btn' + (src === null ? ' flt-active' : '');
        b.style.cssText = `--fb:${c.bg};--fc:${c.col}`;
        b.dataset.src = src || '';
        b.innerHTML = `${label}${badge ? `<span class="flt-badge">${badge.toLocaleString()}</span>` : ''}`;
        b.onclick = () => {
            document.querySelectorAll('#sourceFilterBar .flt-btn').forEach(x => x.classList.remove('flt-active'));
            b.classList.add('flt-active');
            G_activeSource = src;
            G_page = 0;
            applyFilters();
        };
        return b;
    };

    bar.appendChild(mkBtn('All Sources', null, { bg:'rgba(248,250,252,0.08)', col:'#f8fafc' }));
    // Sort by count descending
    Object.entries(srcCount)
        .sort((a,b) => b[1]-a[1])
        .forEach(([s, cnt], i) => bar.appendChild(mkBtn(s, s, srcColor(i), cnt)));
}

/* ============================================================
   FILTER + PAGINATION ENGINE
   ============================================================ */
function applyFilters() {
    G_filtered = G_allIocs.filter(ioc => {
        // text search
        if (G_query) {
            const v = (ioc.value       || '').toLowerCase();
            const t = (ioc.ioc_type    || '').toLowerCase();
            const s = Array.isArray(ioc.sources) ? ioc.sources.join(' ').toLowerCase() : '';
            const g = Array.isArray(ioc.tags)    ? ioc.tags.join(' ').toLowerCase()    : '';
            if (!v.includes(G_query) && !t.includes(G_query) && !s.includes(G_query) && !g.includes(G_query)) return false;
        }
        // type filter
        if (G_activeType !== null && (ioc.ioc_type || 'unknown') !== G_activeType) return false;
        // source filter
        if (G_activeSource !== null) {
            if (!Array.isArray(ioc.sources) || !ioc.sources.includes(G_activeSource)) return false;
        }
        return true;
    });

    renderPage();
    renderPaginator();
}

function renderPage() {
    const tbody  = document.getElementById('iocTableBody');
    const start  = G_page * PAGE_SIZE;
    const slice  = G_filtered.slice(start, start + PAGE_SIZE);
    G_currentPageIocs = slice;

    // results count
    const rc = document.getElementById('iocResultsCount');
    if (rc) rc.textContent = `${G_filtered.length.toLocaleString()} résultats`;

    tbody.innerHTML = slice.map((ioc, i) => {
        const tc  = typeColor(ioc.ioc_type);
        const src = Array.isArray(ioc.sources) ? ioc.sources.join(', ') : '—';
        const pts = Array.isArray(ioc.ports) && ioc.ports.length ? ioc.ports.join(', ') : '—';
        const tgs = Array.isArray(ioc.tags)  && ioc.tags.length
            ? ioc.tags.map((t, j) => {
                const c = tagColor(j);
                return `<span class="tag-pill" style="background:${c.bg};color:${c.col}">${esc(t)}</span>`;
              }).join('')
            : '<span style="color:#475569">—</span>';

        return `<tr onclick="openIOCModal(${i})">
            <td class="idx-td">${start + i + 1}</td>
            <td style="color:#60a5fa;font-weight:600;font-family:monospace;font-size:0.82rem;">${esc(ioc.value)}</td>
            <td><span class="type-pill" style="background:${tc.bg};color:${tc.col}">${ioc.ioc_type||'unknown'}</span></td>
            <td style="color:#94a3b8;font-size:0.78rem;font-family:monospace">${esc(pts)}</td>
            <td style="color:#94a3b8;font-size:0.74rem">${esc(src)}</td>
            <td>${tgs}</td>
        </tr>`;
    }).join('');
}

function renderPaginator() {
    const el    = document.getElementById('iocPaginator');
    const total = G_filtered.length;
    const pages = Math.ceil(total / PAGE_SIZE);
    if (!el) return;
    if (pages <= 1) { el.innerHTML = ''; return; }

    const cur = G_page;
    const WIN = 5;
    let lo = Math.max(0, cur - Math.floor(WIN/2));
    let hi = Math.min(pages - 1, lo + WIN - 1);
    if (hi - lo < WIN - 1) lo = Math.max(0, hi - WIN + 1);

    const btn = (label, page, active=false, disabled=false) =>
        `<button class="pg-btn${active?' pg-active':''}" ${disabled?'disabled':''} onclick="goPage(${page})">${label}</button>`;

    let html = btn('‹', cur-1, false, cur===0);

    if (lo > 0) { html += btn('1', 0); if (lo > 1) html += '<span class="pg-dots">…</span>'; }
    for (let p = lo; p <= hi; p++) html += btn(p+1, p, p===cur);
    if (hi < pages-1) { if (hi < pages-2) html += '<span class="pg-dots">…</span>'; html += btn(pages, pages-1); }

    html += btn('›', cur+1, false, cur===pages-1);

    const s = cur*PAGE_SIZE+1, e = Math.min((cur+1)*PAGE_SIZE, total);
    el.innerHTML = `<span class="pg-info">${s.toLocaleString()}–${e.toLocaleString()} / ${total.toLocaleString()}</span>
                    <div class="pg-btns">${html}</div>`;
}

function goPage(p) {
    G_page = p;
    renderPage();
    renderPaginator();
    document.getElementById('iocTableBody').closest('.table-container')
        .scrollIntoView({ behavior:'smooth', block:'start' });
}

/* ============================================================
   IOC MODAL
   ============================================================ */
function openIOCModal(i) {
    const ioc = G_currentPageIocs[i];
    if (!ioc) return;

    const modal = document.getElementById('ioc-modal');
    const body  = document.getElementById('modal-body');

    const tc   = typeColor(ioc.ioc_type);
    const src  = Array.isArray(ioc.sources)  ? ioc.sources  : [];
    const tags = Array.isArray(ioc.tags)      ? ioc.tags.filter(Boolean) : [];
    const pts  = Array.isArray(ioc.ports)     ? ioc.ports    : [];
    const ctx  = Array.isArray(ioc.contexts)  ? ioc.contexts : [];

    const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/gi;
    const linkCve = s => String(s).replace(CVE_RE, m =>
        `<span class="cve-link" onclick="jumpToCve('${m.toUpperCase()}')">${m}</span>`);

    const renderCtxVal = v => {
        if (v === null || v === undefined) return '<em style="color:#475569">null</em>';
        if (typeof v === 'object') return `<pre class="ctx-pre">${esc(JSON.stringify(v,null,2))}</pre>`;
        return linkCve(esc(String(v)));
    };
    const renderCtx = c => {
        if (typeof c !== 'object' || !c) return `<div class="ctx-box"><pre>${linkCve(esc(String(c)))}</pre></div>`;
        return `<div class="ctx-box">${Object.entries(c).map(([k,v])=>
            `<div class="ctx-row"><span class="ctx-k">${esc(k)}</span><span class="ctx-v">${renderCtxVal(v)}</span></div>`
        ).join('')}</div>`;
    };

    body.innerHTML = `
      <div class="dr">
        <div class="dl">Valeur</div>
        <div style="color:#60a5fa;font-weight:700;font-size:1.35rem;font-family:monospace;word-break:break-all">${esc(ioc.value)}</div>
      </div>
      <div class="dg4">
        <div class="dr"><div class="dl">Type</div>
          <span class="type-pill" style="background:${tc.bg};color:${tc.col}">${ioc.ioc_type||'unknown'}</span></div>
        <div class="dr"><div class="dl">Confiance</div>
          <div>${ioc.confidence!=null ? ioc.confidence+'%' : 'N/A'}</div></div>
        <div class="dr"><div class="dl">Première vue</div>
          <div style="font-size:0.85rem">${ioc.first_seen ? fmtDate(ioc.first_seen) : 'N/A'}</div></div>
        <div class="dr"><div class="dl">Dernière vue</div>
          <div style="font-size:0.85rem">${ioc.last_seen ? fmtDate(ioc.last_seen) : 'N/A'}</div></div>
      </div>
      <div class="dr">
        <div class="dl">Ports</div>
        <div>${pts.length ? pts.map(p=>`<span class="port-pill">${p}</span>`).join('') : '<span style="color:#475569">Aucun port</span>'}</div>
      </div>
      <div class="dr">
        <div class="dl">Sources</div>
        <div>${src.length ? src.map(s=>`<span class="src-pill">${esc(s)}</span>`).join('') : '<span style="color:#475569">N/A</span>'}</div>
      </div>
      <div class="dr">
        <div class="dl">Tags</div>
        <div>${tags.length ? tags.map((t,i)=>{const c=tagColor(i);return`<span class="tag-pill" style="background:${c.bg};color:${c.col};cursor:pointer"
              onclick="filterByTagFromModal('${esc(t)}')" title="Filtrer par ce tag">${esc(t)}</span>`;}).join('') : '<span style="color:#475569">Aucun tag</span>'}</div>
      </div>
      <div class="dr">
        <div class="dl">Contextes</div>
        <div>${ctx.length ? ctx.map(renderCtx).join('') : '<span style="color:#475569">Pas de contexte</span>'}</div>
      </div>`;

    modal.classList.add('active');
}


/* ============================================================
   CVE TABLE + MODAL
   ============================================================ */
function renderCVETable() {
    const tbody = document.getElementById('cveTableBody');
    const start = G_cvePage * PAGE_SIZE;
    const slice = G_filteredCves.slice(start, start + PAGE_SIZE);
    G_visibleCves = slice;

    const rc = document.getElementById('cveResultsCount');
    if (rc) rc.textContent = `${G_filteredCves.length.toLocaleString()} résultats`;

    tbody.innerHTML = slice.map((cve, i) => {
        const yr  = (cve.cve_id||'').split('-')[1]||'N/A';
        const sev = cve.severity || 'N/A';
        const sc  = sevClass(sev);
        const src = Array.isArray(cve.sources) ? cve.sources.join(', ') : 'N/A';
        const dt  = cve.published_date ? fmtDate(cve.published_date) : 'N/A';
        return `<tr onclick="openCVEModal(${i})">
            <td class="idx-td">${start + i + 1}</td>
            <td style="color:#a78bfa;font-weight:600;font-family:monospace">${esc(cve.cve_id||'N/A')}</td>
            <td>${yr}</td>
            <td><span class="sev-pill ${sc}">${sev}</span></td>
            <td style="color:#94a3b8;font-size:0.74rem">${esc(src)}</td>
            <td style="color:#94a3b8;font-size:0.74rem">${dt}</td>
        </tr>`;
    }).join('');
}

function applyCveFilters() {
    const q = document.getElementById('cveSearch').value.toLowerCase().trim();
    G_filteredCves = G_allCves.filter(c => {
        if (!q) return true;
        return (c.cve_id   || '').toLowerCase().includes(q) ||
               (c.severity || '').toLowerCase().includes(q) ||
               (Array.isArray(c.sources) && c.sources.some(s => s.toLowerCase().includes(q)));
    });
    renderCvePage();
}

function renderCvePage() {
    renderCVETable();
    renderCvePaginator();
}

function renderCvePaginator() {
    const el    = document.getElementById('cvePaginator');
    const total = G_filteredCves.length;
    const pages = Math.ceil(total / PAGE_SIZE);
    if (!el) return;
    if (pages <= 1) { el.innerHTML = ''; return; }

    const cur = G_cvePage;
    const WIN = 5;
    let lo = Math.max(0, cur - Math.floor(WIN/2));
    let hi = Math.min(pages - 1, lo + WIN - 1);
    if (hi - lo < WIN - 1) lo = Math.max(0, hi - WIN + 1);

    const btn = (label, page, active=false, disabled=false) =>
        `<button class="pg-btn${active?' pg-active':''}" ${disabled?'disabled':''} onclick="goCvePage(${page})">${label}</button>`;

    let html = btn('‹', cur-1, false, cur===0);

    if (lo > 0) { html += btn('1', 0); if (lo > 1) html += '<span class="pg-dots">…</span>'; }
    for (let p = lo; p <= hi; p++) html += btn(p+1, p, p===cur);
    if (hi < pages-1) { if (hi < pages-2) html += '<span class="pg-dots">…</span>'; html += btn(pages, pages-1); }

    html += btn('›', cur+1, false, cur===pages-1);

    const s = cur*PAGE_SIZE+1, e = Math.min((cur+1)*PAGE_SIZE, total);
    el.innerHTML = `<span class="pg-info">${s.toLocaleString()}–${e.toLocaleString()} / ${total.toLocaleString()}</span>
                    <div class="pg-btns">${html}</div>`;
}

function goCvePage(p) {
    G_cvePage = p;
    renderCvePage();
    document.getElementById('cveTableBody').closest('.table-container')
        .scrollIntoView({ behavior:'smooth', block:'start' });
}

function openCVEModal(i) {
    const cve = G_visibleCves[i];
    if (!cve) return;

    const modal = document.getElementById('cve-modal');
    const body  = document.getElementById('cve-modal-body');
    const src   = Array.isArray(cve.sources) ? cve.sources : [];
    const cvss  = Array.isArray(cve.cvss) ? cve.cvss : (cve.cvss ? [cve.cvss] : []);
    const ctx   = Array.isArray(cve.contexts) ? cve.contexts : [];
    const sev   = cve.severity||'N/A';
    const sc    = sevClass(sev);

    const renderCvssEntry = e => {
        if (typeof e !== 'object') return `<span>${esc(String(e))}</span>`;
        return `<div class="ctx-box">${Object.entries(e).map(([k,v])=>
            `<div class="ctx-row"><span class="ctx-k">${esc(k)}</span><span class="ctx-v">${esc(String(v))}</span></div>`).join('')}</div>`;
    };
    const renderCtx = c => {
        if (typeof c!=='object'||!c) return `<div class="ctx-box">${esc(String(c))}</div>`;
        return `<div class="ctx-box">${Object.entries(c).map(([k,v])=>
            `<div class="ctx-row"><span class="ctx-k">${esc(k)}</span><span class="ctx-v">${typeof v==='object'?`<pre class="ctx-pre">${esc(JSON.stringify(v,null,2))}</pre>`:esc(String(v))}</span></div>`).join('')}</div>`;
    };

    body.innerHTML = `
      <div class="dr">
        <div class="dl">CVE Identifiant</div>
        <div style="color:#a78bfa;font-weight:700;font-size:1.4rem;font-family:monospace">${esc(cve.cve_id||'N/A')}</div>
      </div>
      <div class="dg4">
        <div class="dr"><div class="dl">Sévérité</div>
          <span class="sev-pill ${sc}" style="font-size:0.9rem">${sev}</span></div>
        <div class="dr"><div class="dl">Année</div>
          <div>${(cve.cve_id||'').split('-')[1]||'N/A'}</div></div>
        <div class="dr"><div class="dl">Publication</div>
          <div style="font-size:0.85rem">${cve.published_date ? fmtDate(cve.published_date) : 'N/A'}</div></div>
      </div>
      <div class="dr">
        <div class="dl">Sources</div>
        <div>${src.length ? src.map(s=>`<span class="src-pill">${esc(s)}</span>`).join('') : '<span style="color:#475569">N/A</span>'}</div>
      </div>
      <div class="dr">
        <div class="dl">Scores CVSS</div>
        <div>${cvss.length ? cvss.map(renderCvssEntry).join('') : '<span style="color:#475569">Pas de CVSS</span>'}</div>
      </div>
      <div class="dr">
        <div class="dl">Contextes</div>
        <div>${ctx.length ? ctx.map(renderCtx).join('') : '<span style="color:#475569">Pas de contexte</span>'}</div>
      </div>`;

    modal.classList.add('active');
}

/* ============================================================
   JUMP TO CVE FROM IOC CONTEXT
   ============================================================ */
function jumpToCve(cveId) {
    document.getElementById('ioc-modal').classList.remove('active');
    document.querySelectorAll('.sidebar nav li').forEach(i => i.classList.remove('active'));
    document.querySelectorAll('.dashboard-section').forEach(s => s.classList.remove('active'));
    document.querySelector('[data-section="cves"]').classList.add('active');
    document.getElementById('cves').classList.add('active');
    document.getElementById('section-title').innerText = 'CVEs';
    const input = document.getElementById('cveSearch');
    input.value = cveId;
    input.dispatchEvent(new Event('input'));
}

/* ============================================================
   MODALS SETUP
   ============================================================ */
function setupModals() {
    const iocM = document.getElementById('ioc-modal');
    const cveM = document.getElementById('cve-modal');
    document.getElementById('close-modal').onclick     = () => iocM.classList.remove('active');
    document.getElementById('close-cve-modal').onclick = () => cveM.classList.remove('active');
    window.addEventListener('click', e => {
        if (e.target === iocM) iocM.classList.remove('active');
        if (e.target === cveM) cveM.classList.remove('active');
    });
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') { iocM.classList.remove('active'); cveM.classList.remove('active'); }
    });
}

/* ============================================================
   NAVIGATION
   ============================================================ */
function setupNavigation() {
    const items    = document.querySelectorAll('.sidebar nav li');
    const sections = document.querySelectorAll('.dashboard-section');
    const title    = document.getElementById('section-title');
    items.forEach(item => item.addEventListener('click', () => {
        items.forEach(i   => i.classList.remove('active'));
        sections.forEach(s => s.classList.remove('active'));
        item.classList.add('active');
        document.getElementById(item.dataset.section).classList.add('active');
        title.innerText = item.innerText.trim();
    }));
}

/* ============================================================
   HELPERS
   ============================================================ */
function esc(s) {
    return String(s)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function fmtDate(s) {
    try { return new Date(s).toLocaleString('fr-FR',{dateStyle:'medium',timeStyle:'short'}); }
    catch { return String(s); }
}
function sevClass(s) {
    const u = (s||'').toUpperCase();
    if (u==='CRITICAL') return 'sev-c';
    if (u==='HIGH')     return 'sev-h';
    if (u==='MEDIUM')   return 'sev-m';
    if (u==='LOW')      return 'sev-l';
    return 'sev-n';
}
