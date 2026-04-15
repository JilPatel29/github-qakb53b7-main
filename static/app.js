const API_URL = '/api';

let riskChart = null;
let typeChart = null;
let techniquesChart = null;
let tacticsChart = null;
let allIndicators = [];
let allLogs = [];
let allMitre = [];

function showLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.classList.add('active');
    }
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.classList.remove('active');
    }
}

async function fetchData(endpoint) {
    try {
        const response = await fetch(`${API_URL}${endpoint}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Fetch error:', error);
        showError(`Failed to load data from ${endpoint}`);
        return null;
    }
}

function showError(message) {
    console.error('Error:', message);
}

async function loadStats() {
    const stats = await fetchData('/stats');
    if (stats) {
        const totalEl = document.getElementById('totalIndicators');
        const highEl = document.getElementById('highRisk');
        const mediumEl = document.getElementById('mediumRisk');
        const correlEl = document.getElementById('logCorrelations');

        if (totalEl) totalEl.textContent = stats.total_indicators;
        if (highEl) highEl.textContent = stats.high_risk;
        if (mediumEl) mediumEl.textContent = stats.medium_risk;
        if (correlEl) correlEl.textContent = stats.log_correlations;
    }
}

async function loadRiskChart() {
    const data = await fetchData('/risk-distribution');
    if (!data) return;

    const ctx = document.getElementById('riskChart');
    if (!ctx) return;

    if (riskChart) {
        riskChart.destroy();
    }

    riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.labels,
            datasets: [{
                data: data.values,
                backgroundColor: [
                    '#ff4757',
                    '#ffa502',
                    '#2ed573'
                ],
                borderWidth: 2,
                borderColor: '#1a2142',
                hoverOffset: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        font: {
                            size: 13,
                            weight: '600'
                        },
                        color: '#8b92b0',
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(19, 26, 53, 0.95)',
                    padding: 12,
                    titleFont: {
                        size: 14,
                        weight: 'bold'
                    },
                    bodyFont: {
                        size: 13
                    },
                    cornerRadius: 8,
                    borderColor: '#2a3454',
                    borderWidth: 1
                }
            }
        }
    });
}

async function loadTypeChart() {
    const data = await fetchData('/type-distribution');
    if (!data) return;

    const ctx = document.getElementById('typeChart');
    if (!ctx) return;

    if (typeChart) {
        typeChart.destroy();
    }

    typeChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.labels,
            datasets: [{
                label: 'Count',
                data: data.values,
                backgroundColor: '#00d4ff',
                borderRadius: 10,
                borderWidth: 0,
                hoverBackgroundColor: '#00bfea'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(19, 26, 53, 0.95)',
                    padding: 12,
                    titleFont: {
                        size: 14,
                        weight: 'bold'
                    },
                    bodyFont: {
                        size: 13
                    },
                    cornerRadius: 8
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0,
                        font: {
                            size: 12,
                            weight: '600'
                        },
                        color: '#8b92b0'
                    },
                    grid: {
                        color: 'rgba(42, 52, 84, 0.3)'
                    },
                    border: {
                        color: '#2a3454'
                    }
                },
                x: {
                    ticks: {
                        font: {
                            size: 12,
                            weight: '600'
                        },
                        color: '#8b92b0'
                    },
                    grid: {
                        display: false
                    },
                    border: {
                        color: '#2a3454'
                    }
                }
            }
        }
    });
}

function renderIndicators(indicators) {
    const tbody = document.getElementById('indicatorsBody');
    if (!tbody) return;

    if (!indicators || indicators.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading">No high-risk indicators found</td></tr>';
        return;
    }

    tbody.innerHTML = indicators.map(ind => `
        <tr>
            <td><code>${escapeHtml(ind.indicator)}</code></td>
            <td><span style="text-transform: uppercase; font-weight: 600; color: #8b92b0;">${escapeHtml(ind.type)}</span></td>
            <td><strong>${ind.risk_score.toFixed(2)}</strong></td>
            <td><span class="risk-badge risk-${ind.risk_level.toLowerCase()}">${escapeHtml(ind.risk_level)}</span></td>
            <td>${escapeHtml(ind.threat_category)}</td>
            <td>${escapeHtml(ind.country)}</td>
        </tr>
    `).join('');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function loadHighRiskIndicators() {
    const indicators = await fetchData('/indicators/high-risk');
    renderIndicators(indicators);
}

async function loadDashboard() {
    showLoading();
    await Promise.all([
        loadStats(),
        loadRiskChart(),
        loadTypeChart(),
        loadHighRiskIndicators()
    ]);
    hideLoading();
}

async function loadThreats() {
    showLoading();
    const data = await fetchData('/indicators/all');
    allIndicators = data || [];

    if (allIndicators.length > 0) {
        const categories = [...new Set(allIndicators.map(i => i.threat_category))];
        const categoryFilter = document.getElementById('categoryFilter');
        if (categoryFilter && categoryFilter.options.length <= 1) {
            categories.forEach(cat => {
                const option = document.createElement('option');
                option.value = cat;
                option.textContent = cat;
                categoryFilter.appendChild(option);
            });
        }
    }

    renderThreats(allIndicators);
    setupThreatFilters();
    hideLoading();
}

function renderThreats(indicators) {
    const tbody = document.getElementById('threatsBody');
    if (!tbody) return;

    if (!indicators || indicators.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading">No threat indicators found</td></tr>';
        return;
    }

    tbody.innerHTML = indicators.map(ind => `
        <tr>
            <td><code>${escapeHtml(ind.indicator)}</code></td>
            <td><span style="text-transform: uppercase; font-weight: 600; color: #8b92b0;">${escapeHtml(ind.type)}</span></td>
            <td><strong>${ind.risk_score.toFixed(2)}</strong></td>
            <td><span class="risk-badge risk-${ind.risk_level.toLowerCase()}">${escapeHtml(ind.risk_level)}</span></td>
            <td>${escapeHtml(ind.threat_category)}</td>
            <td>${escapeHtml(ind.country)}</td>
        </tr>
    `).join('');
}

function setupThreatFilters() {
    const searchInput = document.getElementById('searchInput');
    const riskFilter = document.getElementById('riskFilter');
    const typeFilter = document.getElementById('typeFilter');
    const categoryFilter = document.getElementById('categoryFilter');

    function applyFilters() {
        const searchQuery = searchInput ? searchInput.value.toLowerCase() : '';
        const riskValue = riskFilter ? riskFilter.value : '';
        const typeValue = typeFilter ? typeFilter.value : '';
        const categoryValue = categoryFilter ? categoryFilter.value : '';

        let filtered = allIndicators.filter(ind => {
            const matchesSearch = !searchQuery ||
                ind.indicator.toLowerCase().includes(searchQuery) ||
                ind.type.toLowerCase().includes(searchQuery) ||
                ind.threat_category.toLowerCase().includes(searchQuery) ||
                ind.country.toLowerCase().includes(searchQuery);

            const matchesRisk = !riskValue || ind.risk_level === riskValue;
            const matchesType = !typeValue || ind.type === typeValue;
            const matchesCategory = !categoryValue || ind.threat_category === categoryValue;

            return matchesSearch && matchesRisk && matchesType && matchesCategory;
        });

        renderThreats(filtered);
    }

    if (searchInput) searchInput.addEventListener('input', applyFilters);
    if (riskFilter) riskFilter.addEventListener('change', applyFilters);
    if (typeFilter) typeFilter.addEventListener('change', applyFilters);
    if (categoryFilter) categoryFilter.addEventListener('change', applyFilters);
}

async function loadLogs() {
    showLoading();
    const data = await fetchData('/log-matches');
    allLogs = data || [];

    const highRisk = allLogs.filter(log => log.risk_level === 'High').length;
    const mediumRisk = allLogs.filter(log => log.risk_level === 'Medium').length;

    const highEl = document.getElementById('highRiskMatches');
    const mediumEl = document.getElementById('mediumRiskMatches');
    const totalEl = document.getElementById('totalMatches');

    if (highEl) highEl.textContent = highRisk;
    if (mediumEl) mediumEl.textContent = mediumRisk;
    if (totalEl) totalEl.textContent = allLogs.length;

    renderLogs(allLogs);
    setupLogSearch();
    hideLoading();
}

function renderLogs(logs) {
    const tbody = document.getElementById('logsBody');
    if (!tbody) return;

    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading">No suspicious network activity detected</td></tr>';
        return;
    }

    tbody.innerHTML = logs.map(log => `
        <tr>
            <td><small style="color: var(--text-secondary);">${escapeHtml(log.timestamp)}</small></td>
            <td><code>${escapeHtml(log.source_ip)}</code></td>
            <td><code>${escapeHtml(log.destination_ip || log.destination_domain || 'N/A')}</code></td>
            <td><code style="color: var(--warning);">${escapeHtml(log.matched_indicator)}</code></td>
            <td><span style="text-transform: uppercase; font-weight: 600; color: #8b92b0;">${escapeHtml(log.indicator_type)}</span></td>
            <td><span class="risk-badge risk-${log.risk_level.toLowerCase()}">${escapeHtml(log.risk_level)}</span></td>
        </tr>
    `).join('');
}

function setupLogSearch() {
    const searchInput = document.getElementById('searchInput');
    if (!searchInput) return;

    searchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();

        const filtered = allLogs.filter(log =>
            log.source_ip.toLowerCase().includes(query) ||
            (log.destination_ip && log.destination_ip.toLowerCase().includes(query)) ||
            (log.destination_domain && log.destination_domain.toLowerCase().includes(query)) ||
            log.matched_indicator.toLowerCase().includes(query)
        );

        renderLogs(filtered);
    });
}

async function loadMitre() {
    showLoading();
    const data = await fetchData('/mitre/techniques');
    allMitre = data || [];

    await loadMitreCharts();
    renderMitreTable(allMitre);
    setupMitreSearch();
    hideLoading();
}

async function loadMitreCharts() {
    const techniques = {};
    const tactics = {};

    allMitre.forEach(item => {
        techniques[item.technique] = (techniques[item.technique] || 0) + item.count;
        tactics[item.tactic] = (tactics[item.tactic] || 0) + item.count;
    });

    const topTechniques = Object.entries(techniques)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    const ctx1 = document.getElementById('techniquesChart');
    if (ctx1) {
        if (techniquesChart) techniquesChart.destroy();

        techniquesChart = new Chart(ctx1, {
            type: 'bar',
            data: {
                labels: topTechniques.map(t => t[0]),
                datasets: [{
                    label: 'Detections',
                    data: topTechniques.map(t => t[1]),
                    backgroundColor: '#1e40af',
                    borderRadius: 10,
                    borderWidth: 0,
                    hoverBackgroundColor: '#2563eb'
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        padding: 12,
                        titleFont: {
                            size: 14,
                            weight: 'bold'
                        },
                        bodyFont: {
                            size: 13
                        },
                        cornerRadius: 8
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0,
                            font: {
                                size: 12,
                                weight: '600'
                            }
                        },
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    y: {
                        ticks: {
                            font: {
                                size: 11,
                                weight: '600'
                            }
                        },
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });
    }

    const ctx2 = document.getElementById('tacticsChart');
    if (ctx2) {
        if (tacticsChart) tacticsChart.destroy();

        tacticsChart = new Chart(ctx2, {
            type: 'doughnut',
            data: {
                labels: Object.keys(tactics),
                datasets: [{
                    data: Object.values(tactics),
                    backgroundColor: [
                        '#dc2626',
                        '#f59e0b',
                        '#059669',
                        '#1e40af',
                        '#0284c7'
                    ],
                    borderWidth: 3,
                    borderColor: '#fff',
                    hoverOffset: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            font: {
                                size: 13,
                                weight: '600'
                            },
                            usePointStyle: true,
                            pointStyle: 'circle'
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        padding: 12,
                        titleFont: {
                            size: 14,
                            weight: 'bold'
                        },
                        bodyFont: {
                            size: 13
                        },
                        cornerRadius: 8
                    }
                }
            }
        });
    }
}

function renderMitreTable(data) {
    const tbody = document.getElementById('mitreBody');
    if (!tbody) return;

    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="loading">No MITRE ATT&CK techniques detected</td></tr>';
        return;
    }

    tbody.innerHTML = data.map(item => `
        <tr>
            <td><strong>${escapeHtml(item.technique)}</strong></td>
            <td><span style="background: rgba(0, 212, 255, 0.1); color: var(--accent-primary); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; border: 1px solid rgba(0, 212, 255, 0.2);">${escapeHtml(item.tactic)}</span></td>
            <td><strong>${item.count}</strong></td>
            <td><span class="risk-badge risk-high">${item.count} detections</span></td>
        </tr>
    `).join('');
}

function setupMitreSearch() {
    const searchInput = document.getElementById('searchInput');
    if (!searchInput) return;

    searchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();

        const filtered = allMitre.filter(item =>
            item.technique.toLowerCase().includes(query) ||
            item.tactic.toLowerCase().includes(query)
        );

        renderMitreTable(filtered);
    });
}

async function loadReport() {
    showLoading();

    const stats = await fetchData('/stats');
    const highRiskIndicators = await fetchData('/indicators/high-risk');
    const allIndicators = await fetchData('/indicators/all');
    const mitreData = await fetchData('/mitre/techniques');

    const timestampEl = document.getElementById('reportTimestamp');
    if (timestampEl) {
        timestampEl.textContent = new Date().toLocaleString();
    }

    if (stats) {
        const totalEl = document.getElementById('reportTotalIndicators');
        const highEl = document.getElementById('reportHighRisk');
        const matchesEl = document.getElementById('reportLogMatches');

        if (totalEl) totalEl.textContent = stats.total_indicators;
        if (highEl) highEl.textContent = stats.high_risk;
        if (matchesEl) matchesEl.textContent = stats.log_correlations;
    }

    const highRiskBody = document.getElementById('reportHighRiskTable');
    if (highRiskBody) {
        if (highRiskIndicators && highRiskIndicators.length > 0) {
            highRiskBody.innerHTML = highRiskIndicators.slice(0, 10).map(ind => `
                <tr>
                    <td><code>${escapeHtml(ind.indicator)}</code></td>
                    <td>${escapeHtml(ind.type)}</td>
                    <td>${ind.risk_score.toFixed(2)}</td>
                    <td>${escapeHtml(ind.threat_category)}</td>
                    <td>${escapeHtml(ind.country)}</td>
                </tr>
            `).join('');
        } else {
            highRiskBody.innerHTML = '<tr><td colspan="5" class="loading">No high-risk indicators found</td></tr>';
        }
    }

    const reportAllIndicators = allIndicators || [];
    const categories = {};
    reportAllIndicators.forEach(ind => {
        categories[ind.threat_category] = (categories[ind.threat_category] || 0) + 1;
    });
    const total = reportAllIndicators.length;
    const categoryBody = document.getElementById('reportCategoriesTable');
    if (categoryBody) {
        const entries = Object.entries(categories).sort((a, b) => b[1] - a[1]).slice(0, 5);
        if (entries.length > 0) {
            categoryBody.innerHTML = entries.map(([cat, count]) => `
                <tr>
                    <td>${escapeHtml(cat)}</td>
                    <td>${count}</td>
                    <td>${total > 0 ? ((count / total) * 100).toFixed(1) : 0}%</td>
                </tr>
            `).join('');
        } else {
            categoryBody.innerHTML = '<tr><td colspan="3" class="loading">No data available</td></tr>';
        }
    }

    const mitreBody = document.getElementById('reportMitreTable');
    if (mitreBody) {
        if (mitreData && mitreData.length > 0) {
            mitreBody.innerHTML = mitreData.slice(0, 10).map(item => `
                <tr>
                    <td>${escapeHtml(item.technique)}</td>
                    <td>${escapeHtml(item.tactic)}</td>
                    <td>${item.count}</td>
                </tr>
            `).join('');
        } else {
            mitreBody.innerHTML = '<tr><td colspan="3" class="loading">No MITRE techniques detected</td></tr>';
        }
    }

    hideLoading();
}

const refreshBtn = document.getElementById('refreshBtn');
if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
        window.location.reload();
    });
}

const generateReportBtn = document.getElementById('generateReportBtn');
if (generateReportBtn) {
    generateReportBtn.addEventListener('click', () => {
        loadReport();
    });
}

function initMobileMenu() {
    const sidebar = document.querySelector('.sidebar');
    if (!sidebar) return;

    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'sidebar-toggle';
    toggleBtn.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M3 12h18M3 6h18M3 18h18"/>
        </svg>
    `;
    document.body.appendChild(toggleBtn);

    toggleBtn.addEventListener('click', () => {
        sidebar.classList.toggle('active');
    });

    document.addEventListener('click', (e) => {
        if (!sidebar.contains(e.target) && !toggleBtn.contains(e.target)) {
            sidebar.classList.remove('active');
        }
    });
}

if (document.querySelector('.sidebar')) {
    initMobileMenu();
}

function updateActiveNavLink() {
    const currentPath = window.location.pathname;
    const navItems = document.querySelectorAll('.nav-item');

    navItems.forEach(item => {
        const href = item.getAttribute('href');
        if (href === currentPath || (currentPath === '/' && href === '/')) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });
}

if (document.querySelector('.sidebar')) {
    updateActiveNavLink();
}
