document.addEventListener('DOMContentLoaded', async () => {
    lucide.createIcons();
    const statusEl = document.getElementById('loading-status');
    const overlay = document.getElementById('loading-overlay');

    try {
        // Paths relative to the root of the server
        statusEl.innerText = "Fetching IOCs (320MB)...";
        const iocResponse = await fetch('/output_regex/iocs_extracted.json');
        if (!iocResponse.ok) throw new Error('Failed to load IOCs');
        const iocs = await iocResponse.json();

        statusEl.innerText = "Fetching CVEs (230MB)...";
        const cveResponse = await fetch('/output_regex/cves_extracted.json');
        if (!cveResponse.ok) throw new Error('Failed to load CVEs');
        const cves = await cveResponse.json();

        statusEl.innerText = "Processing Data...";
        
        // 1. Update Core Stats
        document.getElementById('total-iocs').innerText = iocs.length.toLocaleString();
        document.getElementById('total-cves').innerText = cves.length.toLocaleString();

        // 2. Generate Distribution Data
        const iocTypes = iocs.reduce((acc, curr) => {
            const type = curr.ioc_type || 'unknown';
            acc[type] = (acc[type] || 0) + 1;
            return acc;
        }, {});

        const cveYears = cves.reduce((acc, curr) => {
            const id = curr.cve_id || '';
            const year = id.split('-')[1] || 'Unknown';
            acc[year] = (acc[year] || 0) + 1;
            return acc;
        }, {});

        // 3. Render Charts
        renderIOCDistribution(iocTypes);
        renderCVETrend(cveYears);

        // 4. Initial Table Population (latest items)
        populateIOCTable(iocs.slice(-200).reverse());
        populateCVETable(cves.slice(-200).reverse());

        // 5. Navigation Logic
        setupNavigation();

        // 6. Search Logic
        setupSearch(iocs, cves);

        // 7. Modal Closing Logic
        setupModal();

        // Hide Loading Overlay
        overlay.style.opacity = '0';
        setTimeout(() => overlay.style.display = 'none', 500);

    } catch (error) {
        console.error(error);
        statusEl.innerHTML = `<span style="color: #ff5555">Error: ${error.message}<br>Make sure to run the server with start_dashboard.py</span>`;
    }
});

function renderIOCDistribution(iocTypes) {
    const ctx = document.getElementById('iocDistributionChart').getContext('2d');
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: Object.keys(iocTypes),
            datasets: [{
                data: Object.values(iocTypes),
                backgroundColor: ['#9b51e0', '#2f80ed', '#eb5757', '#f2c94c', '#27ae60'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8' } }
            }
        }
    });
}

function renderCVETrend(cveYears) {
    const ctx = document.getElementById('cveTrendChart').getContext('2d');
    const sortedYears = Object.keys(cveYears).sort();
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: sortedYears,
            datasets: [{
                label: 'CVEs',
                data: sortedYears.map(y => cveYears[y]),
                borderColor: '#2f80ed',
                backgroundColor: 'rgba(47, 128, 237, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { grid: { color: 'rgba(148, 163, 184, 0.1)' }, ticks: { color: '#94a3b8' } },
                x: { ticks: { color: '#94a3b8' } }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

let currentVisibleIocs = [];

function populateIOCTable(iocs) {
    const tbody = document.getElementById('iocTableBody');
    currentVisibleIocs = iocs.slice(0, 100);
    
    tbody.innerHTML = currentVisibleIocs.map((ioc, index) => {
        const sourcesText = Array.isArray(ioc.sources) ? ioc.sources.join(', ') : (ioc.source || 'N/A');
        const detailsText = Array.isArray(ioc.contexts) && ioc.contexts.length > 0 
            ? (typeof ioc.contexts[0] === 'string' ? ioc.contexts[0] : JSON.stringify(ioc.contexts[0])).replace(/[\[\]]/g, '').slice(0, 80) + '...' 
            : 'No direct context available';
        
        return `
            <tr onclick="showIOCDetails(${index})">
                <td class="index-td">${index + 1}</td>
                <td style="color: #2f80ed; font-weight: 600;">${ioc.value}</td>
                <td><span class="badge ${ioc.ioc_type}">${ioc.ioc_type}</span></td>
                <td style="color: #94a3b8; font-size: 0.75rem;">${sourcesText}</td>
                <td class="details-td">${detailsText}</td>
            </tr>
        `;
    }).join('');
}

function showIOCDetails(index) {
    const ioc = currentVisibleIocs[index];
    if (!ioc) return;

    const modal = document.getElementById('ioc-modal');
    const modalBody = document.getElementById('modal-body');
    
    const sources = Array.isArray(ioc.sources) ? ioc.sources : [ioc.source || 'N/A'];
    const contexts = Array.isArray(ioc.contexts) ? ioc.contexts : (ioc.details ? [ioc.details] : []);

    modalBody.innerHTML = `
        <div class="detail-row">
            <div class="detail-label">Indicator Value</div>
            <div class="detail-value" style="color: var(--secondary); font-weight: 700; font-size: 1.5rem;">${ioc.value}</div>
        </div>
        
        <div class="detail-row">
            <div class="detail-label">Indicator Type</div>
            <div><span class="badge ${ioc.ioc_type}" style="font-size: 1rem; padding: 0.5rem 1rem;">${ioc.ioc_type}</span></div>
        </div>

        <div class="detail-row">
            <div class="detail-label">Sources</div>
            <div class="detail-value">
                ${sources.map(s => `<span class="source-tag">${s}</span>`).join('')}
            </div>
        </div>

        <div class="detail-row">
            <div class="detail-label">Contexts & Metadata</div>
            <div class="detail-value">
                ${contexts.length > 0 ? contexts.map(c => `
                    <div class="context-box" style="margin-bottom: 1rem;">
                        ${typeof c === 'object' ? `<pre>${JSON.stringify(c, null, 2)}</pre>` : c}
                    </div>
                `).join('') : '<p style="color: var(--text-secondary)">No additional context found for this indicator.</p>'}
            </div>
        </div>
    `;

    modal.classList.add('active');
}

function setupModal() {
    const modal = document.getElementById('ioc-modal');
    const closeBtn = document.getElementById('close-modal');

    closeBtn.onclick = () => modal.classList.remove('active');
    
    window.onclick = (event) => {
        if (event.target == modal) {
            modal.classList.remove('active');
        }
    };

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && modal.classList.contains('active')) {
            modal.classList.remove('active');
        }
    });
}

function populateCVETable(cves) {
    const tbody = document.getElementById('cveTableBody');
    tbody.innerHTML = cves.slice(0, 100).map(cve => `
        <tr>
            <td style="color: #9b51e0; font-weight: 500;">${cve.cve_id}</td>
            <td>${cve.cve_id.split('-')[1] || 'N/A'}</td>
            <td>${cve.lastModified || 'N/A'}</td>
        </tr>
    `).join('');
}

function setupNavigation() {
    const navItems = document.querySelectorAll('.sidebar nav li');
    const sections = document.querySelectorAll('.dashboard-section');
    const sectionTitle = document.getElementById('section-title');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const sectionId = item.getAttribute('data-section');
            navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            sections.forEach(s => s.classList.remove('active'));
            document.getElementById(sectionId).classList.add('active');
            sectionTitle.innerText = item.innerText;
        });
    });
}

function setupSearch(allIocs, allCves) {
    const iocSearch = document.getElementById('iocSearch');
    const cveSearch = document.getElementById('cveSearch');

    iocSearch.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const filtered = allIocs.filter(ioc => 
            ioc.value.toLowerCase().includes(query) || 
            ioc.ioc_type.toLowerCase().includes(query) ||
            (Array.isArray(ioc.sources) && ioc.sources.some(s => s.toLowerCase().includes(query)))
        ).slice(0, 100);
        populateIOCTable(filtered);
    });

    cveSearch.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const filtered = allCves.filter(cve => 
            cve.cve_id.toLowerCase().includes(query)
        ).slice(0, 100);
        populateCVETable(filtered);
    });
}
