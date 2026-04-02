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
let G_activeCountry = null; // e.g. "United States"
let G_query        = '';   // text search

let G_currentPageIocs = []; // IOCs on screen (for modal)
let G_visibleCves     = []; // CVEs on screen (for modal)
let G_allCves         = []; // full CVE dataset
let G_filteredCves    = []; // after search
let G_cvePage         = 0;    // current page index for CVEs
let G_activeCveSource = null; // e.g. "nvd"

// Colour palettes
const TYPE_COLORS = {
    ip:      { bg: 'rgba(139, 92, 246, 0.18)', col: '#a78bfa' }, // Violet
    url:     { bg: 'rgba(245, 158, 11, 0.18)',  col: '#fbbf24' }, // Amber
    domain:  { bg: 'rgba(16, 185, 129, 0.18)', col: '#34d399' }, // Emerald
    sha256:  { bg: 'rgba(249, 115, 22, 0.18)',  col: '#fb923c' }, // Orange
    sha1:    { bg: 'rgba(239, 68, 68, 0.18)',  col: '#f87171' }, // Red
    md5:     { bg: 'rgba(244, 63, 94, 0.18)',  col: '#fb7185' }, // Rose
    email:   { bg: 'rgba(192, 132, 252, 0.18)', col: '#d8b4fe' }, // Light Purple
    unknown: { bg: 'rgba(100, 116, 139, 0.18)', col: '#94a3b8' },
};
function typeColor(t) { return TYPE_COLORS[t] || TYPE_COLORS.unknown; }

const TAG_PALETTE = [
    { bg: 'rgba(139, 92, 246, 0.18)', col: '#a78bfa' },
    { bg: 'rgba(245, 158, 11, 0.18)', col: '#fbbf24' },
    { bg: 'rgba(16, 185, 129, 0.18)', col: '#34d399' },
    { bg: 'rgba(249, 115, 22, 0.18)', col: '#fb923c' },
    { bg: 'rgba(239, 68, 68, 0.18)',  col: '#f87171' },
    { bg: 'rgba(244, 63, 94, 0.18)',  col: '#fb7185' },
    { bg: 'rgba(168, 85, 247, 0.18)', col: '#c084fc' },
    { bg: 'rgba(234, 179, 8, 0.18)',  col: '#facc15' },
];
const tagColor = (i) => TAG_PALETTE[i % TAG_PALETTE.length];

/* ============================================================
   BOOT
   ============================================================ */
document.addEventListener('DOMContentLoaded', async () => {
    lucide.createIcons();
    const statusEl = document.getElementById('loading-status');
    const overlay  = document.getElementById('loading-overlay');
    const barEl    = document.getElementById('loader-bar');

    const setLoad = (msg, pct) => {
        if (statusEl) statusEl.innerText = msg;
        if (barEl) barEl.style.width = pct + '%';
    };

    try {
        setLoad('Authenticating to Central Threat Intelligence...', 10);
        await new Promise(r => setTimeout(r, 400)); // aesthetic delay

        setLoad('Streaming IOC repository (320 MB)...', 25);
        const iocRes = await fetch('/output_regex/iocs_extracted.json');
        if (!iocRes.ok) throw new Error('IOCs fetch failed');
        const iocs = await iocRes.json();
        setLoad('IOC repository synchronized.', 45);

        setLoad('Fetching CVE vulnerability signatures (230 MB)...', 55);
        const cveRes = await fetch('/output_regex/cves_extracted.json');
        if (!cveRes.ok) throw new Error('CVEs fetch failed');
        const cves = await cveRes.json();
        setLoad('Vulnerability signatures synchronized.', 75);

        setLoad('Mapping global threat vectors...', 85);
        window._cveIndex = Object.fromEntries(
            cves.filter(c => c.cve_id).map(c => [c.cve_id.toUpperCase(), c])
        );

        document.getElementById('total-iocs').innerText = iocs.length.toLocaleString();
        document.getElementById('total-cves').innerText = cves.length.toLocaleString();

        // Compute unique IOC sources
        const iocSourceCount = {};
        iocs.forEach(i => { if(Array.isArray(i.sources)) i.sources.forEach(s => { if(s) iocSourceCount[s] = (iocSourceCount[s]||0)+1; }); });
        document.getElementById('total-ioc-sources').innerText = Object.keys(iocSourceCount).length.toLocaleString();

        // Compute unique CVE sources
        const cveSourceCount = {};
        cves.forEach(c => { if(Array.isArray(c.sources)) c.sources.forEach(s => { if(s) cveSourceCount[s] = (cveSourceCount[s]||0)+1; }); });
        document.getElementById('total-cve-sources').innerText = Object.keys(cveSourceCount).length.toLocaleString();

        // Compute countries
        const countryCount = {};
        const countryToCode = {};
        iocs.forEach(i => {
            if (Array.isArray(i.contexts)) {
                for (let c of i.contexts) {
                    if (c && (c.countryName || c.countryCode)) {
                        let cname = c.countryName || c.countryCode;
                        countryCount[cname] = (countryCount[cname]||0)+1;
                        if (c.countryCode && !countryToCode[cname]) {
                            countryToCode[cname] = c.countryCode;
                        }
                        break;
                    }
                }
            }
        });

        setLoad('Rendering visualization layers...', 95);

        // Charts
        const typeCount = {};
        iocs.forEach(i => { const t = i.ioc_type || 'unknown'; typeCount[t] = (typeCount[t]||0)+1; });
        renderIOCDistribution(typeCount);
        renderTypeBreakdown(typeCount, iocs.length);

        const yearCount = {};
        cves.forEach(c => { const y = (c.cve_id||'').split('-')[1]||'?'; yearCount[y]=(yearCount[y]||0)+1; });
        renderCVETrend(yearCount);

        // Bar charts
        renderBarChart('countryChart', countryCount, '#8b5cf6');   // Purple
        renderBarChart('iocSourcesChart', iocSourceCount, '#f59e0b'); // Amber
        renderBarChart('cveSourcesChart', cveSourceCount, '#10b981'); // Emerald

        // IOC section
        G_allIocs = iocs;
        buildTypeFilters(typeCount);
        buildSourceFilters(iocs);
        buildCountryFilters(countryCount, countryToCode);
        applyFilters();

        // CVE section
        G_allCves = cves.reverse();
        buildCveSourceFilters(cves);
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

        setLoad('System Ready. Decrypting environment...', 100);
        
        setTimeout(() => {
            overlay.style.opacity = '0';
            setTimeout(() => overlay.style.display = 'none', 800);
        }, 600);

    } catch (err) {
        console.error(err);
        if (statusEl) {
            statusEl.innerHTML = `<span style="color:#f87171">Fatal Execution Error: ${err.message}</span>`;
        }
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
            datasets: [{ data: Object.values(typeCount), borderWidth: 2, borderColor: '#0b0e14',
                backgroundColor: ['#8b5cf6','#f59e0b','#10b981','#f97316','#ef4444','#ec4899','#a855f7'] }]
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

function renderBarChart(canvasId, dataCount, bgColor) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const sorted = Object.entries(dataCount).sort((a,b) => b[1]-a[1]).slice(0, 7);
    const labels = sorted.map(x => x[0].length > 15 ? x[0].substring(0, 15) + '...' : x[0]);
    const data = sorted.map(x => x[1]);

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{ data: data, backgroundColor: bgColor, borderRadius: 4 }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(148,163,184,0.1)' }, ticks: { color: '#94a3b8' } },
                y: { grid: { display: false }, ticks: { color: '#94a3b8' } }
            }
        }
    });
}

function renderCVETrend(yearCount) {
    const yrs = Object.keys(yearCount).sort();
    new Chart(document.getElementById('cveTrendChart'), {
        type: 'line',
        data: {
            labels: yrs,
            datasets: [{ label:'CVEs', data: yrs.map(y=>yearCount[y]),
                borderColor:'#10b981', backgroundColor:'rgba(16, 185, 129, 0.1)',
                shadowBlur: 10, shadowColor: 'rgba(16, 185, 129, 0.5)',
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

function buildCountryFilters(countryCount, countryToCode) {
    const bar = document.getElementById('countryFilterBar');
    if (!bar) return;
    bar.innerHTML = '';
    if (Object.keys(countryCount).length === 0) {
        bar.innerHTML = '<span class="no-tags-msg">Aucun pays dans les données</span>';
        return;
    }
    const mkBtn = (label, country, badge, code) => {
        const b = document.createElement('button');
        b.className   = 'flt-btn' + (country === null ? ' flt-active' : '');
        b.style.cssText = `--fb:rgba(47,128,237,0.18);--fc:#60a5fa;display:inline-flex;align-items:center;gap:4px;`;
        let flagHtml = (code && code.length === 2) ? `<img src="https://flagcdn.com/w20/${code.toLowerCase()}.png" width="14" alt="${esc(code)}" style="border-radius:1px;">` : '';
        let displayLabel = (code && code.length >= 2 && code.length <= 3) ? code.toUpperCase() : label;
        b.innerHTML = `${flagHtml}<span>${esc(displayLabel)}</span>${badge ? `<span class="flt-badge">${badge.toLocaleString()}</span>` : ''}`;
        b.onclick = () => {
            document.querySelectorAll('#countryFilterBar .flt-btn').forEach(x => x.classList.remove('flt-active'));
            b.classList.add('flt-active');
            G_activeCountry = country;
            G_page = 0;
            applyFilters();
        };
        return b;
    };
    bar.appendChild(mkBtn('Tous les pays', null));
    Object.entries(countryCount).sort((a,b) => b[1]-a[1]).slice(0, 20).forEach(([c, cnt]) => bar.appendChild(mkBtn(c, c, cnt, countryToCode[c])));
}

function buildCveSourceFilters(cves) {
    const bar = document.getElementById('cveSourceFilterBar');
    if (!bar) return;
    bar.innerHTML = '';

    // Count occurrences per source
    const srcCount = {};
    cves.forEach(cve => {
        if (Array.isArray(cve.sources)) cve.sources.forEach(s => { if(s) srcCount[s] = (srcCount[s]||0)+1; });
    });

    if (Object.keys(srcCount).length === 0) {
        bar.innerHTML = '<span class="no-tags-msg">Aucune source dans les données</span>';
        return;
    }

    const SOURCE_PALETTE = [
        { bg:'rgba(167,139,250,0.18)', col:'#a78bfa' },
        { bg:'rgba(96,165,250,0.18)',  col:'#60a5fa' },
        { bg:'rgba(52,211,153,0.18)',  col:'#34d399' },
        { bg:'rgba(251,146,60,0.18)',  col:'#fb923c' },
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
            document.querySelectorAll('#cveSourceFilterBar .flt-btn').forEach(x => x.classList.remove('flt-active'));
            b.classList.add('flt-active');
            G_activeCveSource = src;
            G_cvePage = 0;
            applyCveFilters();
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
        // country filter
        if (G_activeCountry !== null) {
            let matchesCountry = false;
            if (Array.isArray(ioc.contexts)) {
                for (let c of ioc.contexts) {
                    if (c && (c.countryName || c.countryCode)) {
                        let cname = c.countryName || c.countryCode;
                        if (cname === G_activeCountry) matchesCountry = true;
                        break;
                    }
                }
            }
            if (!matchesCountry) return false;
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
        const tgs = Array.isArray(ioc.tags)  && ioc.tags.length
            ? `<div class="pill-container">${ioc.tags.map((t, j) => {
                const c = tagColor(j);
                return `<span class="tag-pill" style="background:${c.bg};color:${c.col}">${esc(t)}</span>`;
              }).join('')}</div>`
            : '<span style="color:#475569">—</span>';

        let locationHtml = '<span style="color:#475569">—</span>';
        if (Array.isArray(ioc.contexts)) {
            for (let c of ioc.contexts) {
                if (c && (c.countryName || c.countryCode)) {
                    let cname = c.countryName || c.countryCode;
                    let ccode = c.countryCode;
                    let isp = c.isp || '';
                    let flag = (ccode && ccode.length === 2) 
                        ? `<img src="https://flagcdn.com/w20/${ccode.toLowerCase()}.png" width="16" alt="${esc(ccode)}">` 
                        : '';
                    let displayCode = ccode && (ccode.length === 2 || ccode.length === 3) ? ccode.toUpperCase() : cname;
                    locationHtml = `<div class="location-pill">${flag}${esc(displayCode)}</div>`;
                    break;
                }
            }
        }

        return `<tr onclick="openIOCModal(${i})">
            <td class="idx-td">${start + i + 1}</td>
            <td style="color:#60a5fa;font-weight:600;font-family:monospace;font-size:0.82rem;">${esc(ioc.value)}</td>
            <td><span class="type-pill" style="background:${tc.bg};color:${tc.col}">${ioc.ioc_type||'unknown'}</span></td>
            <td>${locationHtml}</td>
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

    let cname = 'N/A', isp = 'N/A', usage = 'N/A', abuseScore = 'N/A', ccode = null;
    if (Array.isArray(ioc.contexts)) {
        for (let c of ioc.contexts) {
            if (c) {
                if (c.countryName || c.countryCode) {
                    cname = c.countryName || c.countryCode;
                    ccode = c.countryCode;
                }
                if (c.isp) isp = c.isp;
                if (c.usageType) usage = c.usageType;
                if (c.abuseConfidenceScore != null) abuseScore = c.abuseConfidenceScore + '%';
            }
        }
    }

    let countryHtml = esc(cname);
    if (ccode && ccode.length === 2 && cname !== 'N/A') {
        let flag = `<img src="https://flagcdn.com/w20/${ccode.toLowerCase()}.png" width="18" alt="${esc(ccode)}" style="margin-right:6px;vertical-align:middle;border-radius:2.5px;box-shadow:0 0 2px rgba(0,0,0,0.5);">`;
        countryHtml = `<div style="display:inline-flex;align-items:center;background:rgba(255,255,255,0.06);padding:0.3rem 0.6rem;border-radius:6px;border:1px solid rgba(255,255,255,0.08);">${flag} <span>${esc(cname)}</span></div>`;
    } else if (cname !== 'N/A') {
        countryHtml = `<div style="display:inline-flex;align-items:center;background:rgba(255,255,255,0.06);padding:0.3rem 0.6rem;border-radius:6px;border:1px solid rgba(255,255,255,0.08);"><span>${esc(cname)}</span></div>`;
    }

    body.innerHTML = `
      <div class="dr">
        <div class="dl">Valeur</div>
        <div style="color:#60a5fa;font-weight:700;font-size:1.35rem;font-family:monospace;word-break:break-all">${esc(ioc.value)}</div>
      </div>
      <div class="dg4">
        <div class="dr"><div class="dl">Type</div>
          <span class="type-pill" style="background:${tc.bg};color:${tc.col}">${ioc.ioc_type||'unknown'}</span></div>
        <div class="dr"><div class="dl">Score Abus</div>
          <div>${abuseScore}</div></div>
        <div class="dr"><div class="dl">Pays</div>
          <div>${countryHtml}</div></div>
        <div class="dr"><div class="dl">ISP / FAI</div>
          <div>${esc(isp)}</div></div>
      </div>
      <!-- Add a second grid to avoid breaking the 4-column layout if it gets too wide -->
      <div class="dg4" style="margin-top:-0.5rem">
        <div class="dr"><div class="dl">Confiance</div>
          <div>${ioc.confidence!=null ? ioc.confidence+'%' : 'N/A'}</div></div>
        <div class="dr"><div class="dl">Usage</div>
          <div>${esc(usage)}</div></div>
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
        const scoop = cve.score != null ? cve.score.toFixed(1) : 'N/A';
        const scc = scoreClass(cve.score);
        const src = Array.isArray(cve.sources) ? cve.sources.join(', ') : 'N/A';
        const dt  = cve.published_date ? fmtDate(cve.published_date) : 'N/A';
        return `<tr onclick="openCVEModal(${i})">
            <td class="idx-td">${start + i + 1}</td>
            <td style="color:#a78bfa;font-weight:600;font-family:monospace">${esc(cve.cve_id||'N/A')}</td>
            <td>${yr}</td>
            <td><span class="sev-pill ${sc}">${sev}</span></td>
            <td><span class="score-pill ${scc}">${scoop}</span></td>
            <td style="color:#94a3b8;font-size:0.74rem">${esc(src)}</td>
            <td style="color:#94a3b8;font-size:0.74rem">${dt}</td>
        </tr>`;
    }).join('');
}

function applyCveFilters() {
    const q = document.getElementById('cveSearch').value.toLowerCase().trim();
    G_filteredCves = G_allCves.filter(c => {
        // source filter
        if (G_activeCveSource !== null) {
            if (!Array.isArray(c.sources) || !c.sources.includes(G_activeCveSource)) return false;
        }

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
    const score = cve.score != null ? cve.score.toFixed(1) : 'N/A';
    const scc   = scoreClass(cve.score);

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
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:1.5rem">
        <div>
          <div class="dl">CVE Identifiant</div>
          <div style="color:#a78bfa;font-weight:700;font-size:1.6rem;font-family:monospace">${esc(cve.cve_id||'N/A')}</div>
        </div>
        <div style="text-align:right">
          <div class="dl">CVSS Score</div>
          <div class="score-pill ${scc}" style="font-size:1.5rem; padding:.4rem .8rem">${score}</div>
        </div>
      </div>

      <div class="dr">
         <div class="dl">Description</div>
         <div class="description-box">${esc(cve.description || 'Aucune description disponible pour cette vulnérabilité.')}</div>
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
        <div class="dl">Détails CVSS</div>
        <div>${cvss.length ? cvss.map(renderCvssEntry).join('') : '<span style="color:#475569">Pas de CVSS</span>'}</div>
      </div>

      <div class="dr">
        <div class="dl">Contextes (Auto-extraction)</div>
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

function scoreClass(s) {
    const n = parseFloat(s);
    if (isNaN(n) || n === 0) return 'sc-n';
    if (n >= 9.0) return 'sc-c';
    if (n >= 7.0) return 'sc-h';
    if (n >= 4.0) return 'sc-m';
    return 'sc-l';
}
