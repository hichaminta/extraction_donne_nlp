document.addEventListener('DOMContentLoaded', async () => {
    // Basic DOM elements checks
    const globalSearchInput = document.getElementById('global-search');
    const updateTimeElem = document.getElementById('update-time');
    const threatListBody = document.getElementById('threat-list-body');

    // Make sure we do not fail if an element is missing from user's DOM modifications
    let allData = [];
    let filteredData = [];
    const itemsPerPage = 20;
    let currentPage = 1;
    let exploitedOnly = false;
    let sortColumn = 'published';
    let sortAscending = false;

    // Base getters
    function getScore(item) {
        if (item && item.cvss && item.cvss.length > 0) return parseFloat(item.cvss[0].score) || 0;
        return item ? (parseFloat(item.score) || 0) : 0;
    }

    function getSeverity(score) {
        score = parseFloat(score) || 0;
        if (score >= 9.0) return { label: 'CRITICAL', cls: 'badge-critical' };
        if (score >= 7.0) return { label: 'HIGH', cls: 'badge-high' };
        if (score >= 4.0) return { label: 'MEDIUM', cls: 'badge-medium' };
        return { label: 'LOW', cls: 'badge-low' };
    }

    async function loadData() {
        try {
            if (updateTimeElem) updateTimeElem.textContent = 'Chargement...';

            const response = await fetch('cve_data_exploited.json');
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const raw = await response.json();
            allData = Object.values(raw.cves || {});
            window._allCveData = allData;

            filteredData = [...allData];

            applyFilters();
            if (updateTimeElem) updateTimeElem.textContent = new Date().toLocaleString();
        } catch (error) {
            console.error('Erreur:', error);
            if (updateTimeElem) updateTimeElem.textContent = 'Erreur';
            if (threatListBody) threatListBody.innerHTML = `<tr><td colspan="5">Erreur: ${error.message}</td></tr>`;
        }
    }

    function applyFilters() {
        const term = globalSearchInput ? globalSearchInput.value.toLowerCase().trim() : '';

        // Safely access multi-selection elements if present in DOM otherwise default ''
        const sevElem = document.getElementById('severity-filter');
        const cvssElem = document.getElementById('cvss-version-filter');
        const yearElem = document.getElementById('year-filter');

        const sevVal = sevElem ? sevElem.value : '';
        const cvssVal = cvssElem ? cvssElem.value : '';
        const yrVal = yearElem ? yearElem.value : '';

        filteredData = allData.filter(item => {
            if (!item) return false;

            if (exploitedOnly && item.exploited !== 1 && item.exploited !== true) return false;
            if (term) {
                const id = (item.cve_id || '').toLowerCase();
                const desc = (item.description || '').toLowerCase();
                if (!id.includes(term) && !desc.includes(term)) return false;
            }

            if (sevVal) {
                const { label } = getSeverity(getScore(item));
                if (label !== sevVal) return false;
            }

            if (yrVal) {
                const dateStr = item.published_date || item.published;
                let itemYear = '';
                if (dateStr) {
                    itemYear = String(dateStr).substring(0, 4);
                } else if (item.cve_id) {
                    const match = String(item.cve_id).match(/^CVE-(\d{4})-/);
                    if (match) itemYear = match[1];
                }
                if (itemYear !== yrVal) return false;
            }

            return true;
        });

        // Sorting explicitly built for robustness
        filteredData.sort((a, b) => {
            let valA, valB;
            if (sortColumn === 'id') {
                valA = a.cve_id || '';
                valB = b.cve_id || '';
            } else if (sortColumn === 'score') {
                valA = getScore(a);
                valB = getScore(b);
            } else {
                valA = new Date(a.published_date || a.published || 0).getTime();
                valB = new Date(b.published_date || b.published || 0).getTime();
            }
            if (valA < valB) return sortAscending ? -1 : 1;
            if (valA > valB) return sortAscending ? 1 : -1;
            return 0;
        });

        currentPage = 1;
        updateDashboard();
        renderTable();
    }

    function updateDashboard() {
        let critical = 0, high = 0, medium = 0, exploited = 0;
        filteredData.forEach(item => {
            const score = getScore(item);
            if (score >= 9.0) critical++;
            else if (score >= 7.0) high++;
            else if (score >= 4.0) medium++;
            if (item.exploited === 1 || item.exploited === true) exploited++;
        });

        const totalElem = document.querySelector('#total-threats .stat-value');
        const critElem = document.querySelector('#critical-count .stat-value');
        const hiElem = document.querySelector('#high-count .stat-value');
        const medElem = document.querySelector('#medium-count .stat-value');
        const explElem = document.querySelector('#exploited-count .stat-value');

        if (totalElem) totalElem.textContent = filteredData.length.toLocaleString();
        if (critElem) critElem.textContent = critical.toLocaleString();
        if (hiElem) hiElem.textContent = high.toLocaleString();
        if (medElem) medElem.textContent = medium.toLocaleString();
        if (explElem) explElem.textContent = exploited.toLocaleString();
    }

    function renderTable() {
        if (!threatListBody) return;
        const start = (currentPage - 1) * itemsPerPage;
        const pageItems = filteredData.slice(start, start + itemsPerPage);
        threatListBody.innerHTML = '';

        if (pageItems.length === 0) {
            threatListBody.innerHTML = `<tr><td colspan="5" style="text-align:center;">Aucun résultat</td></tr>`;
            renderPagination();
            return;
        }

        pageItems.forEach(item => {
            const score = getScore(item);
            const { label, cls } = getSeverity(score);
            const isExploited = item.exploited === 1 || item.exploited === true;
            const badge = isExploited ? `<span class="badge badge-exploited">🔴 EXPLOITÉ</span>` : '';
            const desc = (item.description || 'N/A').substring(0, 120) + '...';
            const pub = item.published_date ? new Date(item.published_date).toLocaleDateString() : (item.published || '—');
            const row = document.createElement('tr');
            if (isExploited) row.classList.add('row-exploited');

            row.innerHTML = `
                <td><strong>${item.cve_id || 'N/A'}</strong></td>
                <td>${pub}</td>
                <td><span class="badge ${cls}">${label} (${score})</span> ${badge}</td>
                <td title="${(item.description || '').replace(/"/g, '&quot;')}">${desc}</td>
                <td><button class="btn-primary btn-sm" onclick="showDetails('${item.cve_id}')">Détails</button></td>
            `;
            threatListBody.appendChild(row);
        });

        renderPagination();

        // Update Sort UI properly
        document.querySelectorAll('th.sortable').forEach(th => {
            const span = th.querySelector('span');
            if (span) {
                if (th.getAttribute('data-sort') === sortColumn) {
                    span.textContent = sortAscending ? '↑' : '↓';
                    span.style.color = '#3b82f6';
                } else {
                    span.textContent = '↕';
                    span.style.color = '#64748b';
                }
            }
        });
    }

    function renderPagination() {
        const totalPages = Math.max(1, Math.ceil(filteredData.length / itemsPerPage));
        const pag = document.getElementById('table-pagination');
        if (!pag) return;
        pag.innerHTML = '';

        const prev = document.createElement('button'); prev.textContent = '←';
        prev.disabled = currentPage === 1;
        prev.onclick = () => { currentPage--; renderTable(); };

        const next = document.createElement('button'); next.textContent = '→';
        next.disabled = currentPage === totalPages;
        next.onclick = () => { currentPage++; renderTable(); };

        const info = document.createElement('span');
        info.textContent = `Page ${currentPage} / ${totalPages}`;
        info.style.margin = '0 10px';

        pag.append(prev, info, next);
    }

    // Attach base events
    if (globalSearchInput) globalSearchInput.addEventListener('input', applyFilters);

    const sevElem = document.getElementById('severity-filter');
    if (sevElem) sevElem.addEventListener('change', applyFilters);
    const yrElem = document.getElementById('year-filter');
    if (yrElem) yrElem.addEventListener('change', applyFilters);
    const cvElem = document.getElementById('cvss-version-filter');
    if (cvElem) cvElem.addEventListener('change', applyFilters);

    document.querySelectorAll('th.sortable').forEach(th => {
        th.style.cursor = 'pointer';
        th.addEventListener('click', () => {
            const col = th.getAttribute('data-sort');
            if (sortColumn === col) sortAscending = !sortAscending;
            else { sortColumn = col; sortAscending = false; }
            applyFilters();
        });
    });

    window.toggleExploitedFilter = function () {
        exploitedOnly = !exploitedOnly;
        const btn = document.getElementById('exploited-filter-btn');
        if (btn) {
            btn.style.background = exploitedOnly ? '#ef4444' : '';
            btn.textContent = exploitedOnly ? '✅ Toutes les CVEs' : '🔴 Exploitées uniquement';
        }
        applyFilters();
    };

    loadData();
});

// Modal Logic
window.showDetails = function (cveId) {
    const modal = document.getElementById('details-modal');
    const modalBody = document.getElementById('modal-details-body');
    if (!modal || !modalBody) return;

    const item = (window._allCveData || []).find(d => d && d.cve_id === cveId);
    if (!item) return;

    const cvss = (item.cvss && item.cvss.length > 0) ? item.cvss[0] : null;
    const score = parseFloat(cvss ? cvss.score : item.score) || 0;
    const vector = cvss ? cvss.vector : (item.vector || 'N/A');

    modalBody.innerHTML = `<div style="font-size: 1.25rem; font-weight: bold; margin-bottom: 20px;">${item.cve_id}</div>
        <div style="margin-bottom: 10px;"><strong>Score:</strong> ${score}</div>
        <div style="margin-bottom: 10px;"><strong>Vecteur:</strong> ${vector}</div>
        <div><strong>Description:</strong> <br>${item.description || 'N/A'}</div>`;
    modal.style.display = 'block';
};

const clsBtn = document.querySelector('.close-modal');
if (clsBtn) clsBtn.onclick = () => { document.getElementById('details-modal').style.display = 'none'; };
window.onclick = (e) => { const m = document.getElementById('details-modal'); if (e.target === m) m.style.display = 'none'; };
