/**
 * Mini SIEM Dashboard - App Logic
 * Handles: tab navigation, data fetching, chart rendering, search, live feed
 */

// ═══════════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════════

const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:8000'
    : `http://${window.location.hostname}:8000`;

const REFRESH_INTERVAL = 30000; // 30 seconds auto-refresh
const LIVEFEED_INTERVAL = 5000; // 5 seconds live feed polling

// ═══════════════════════════════════════════════════════════════
//  State
// ═══════════════════════════════════════════════════════════════

const state = {
    currentTab: 'dashboard',
    timeRange: '24h',
    autoRefresh: true,
    liveFeedActive: true,
    searchPage: 1,
    searchSize: 50,
    charts: {},
    intervals: {},
};

// Chart color palette
const COLORS = {
    blue: '#3b82f6',
    red: '#ef4444',
    orange: '#f59e0b',
    green: '#10b981',
    purple: '#8b5cf6',
    cyan: '#06b6d4',
    pink: '#ec4899',
    yellow: '#eab308',
    indigo: '#6366f1',
    teal: '#14b8a6',
};

const CHART_PALETTE = [
    COLORS.blue, COLORS.red, COLORS.orange, COLORS.green,
    COLORS.purple, COLORS.cyan, COLORS.pink, COLORS.yellow,
    COLORS.indigo, COLORS.teal,
];

// Chart shared config — tooltip & grid scale dùng chung cho tất cả biểu đồ
const CHART_TOOLTIP = {
    backgroundColor: '#1a1f35',
    borderColor: '#2d3a5c',
    borderWidth: 1,
    titleColor: '#e8eaf0',
    bodyColor: '#8b92a8',
    padding: 12,
    cornerRadius: 8,
};

const CHART_LEGEND_LABELS = {
    color: '#8b92a8',
    font: { size: 11, family: 'Inter' },
    padding: 12,
    usePointStyle: true,
};

const CHART_GRID_COLOR = 'rgba(30, 38, 66, 0.5)';
const CHART_TICK_STYLE = { color: '#5c6380', font: { size: 10 } };

// ═══════════════════════════════════════════════════════════════
//  Utility Functions
// ═══════════════════════════════════════════════════════════════

function formatNumber(num) {
    if (num == null || isNaN(num)) return '0';
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toLocaleString();
}

function formatUptime(seconds) {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
}

function formatTimestamp(ts) {
    if (!ts) return '—';
    try {
        const d = new Date(ts);
        return d.toLocaleString('vi-VN', {
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    } catch {
        return ts;
    }
}

function getTimeRange() {
    const now = new Date();
    const ranges = {
        '1h': new Date(now - 3600 * 1000),
        '6h': new Date(now - 6 * 3600 * 1000),
        '24h': new Date(now - 24 * 3600 * 1000),
        '7d': new Date(now - 7 * 24 * 3600 * 1000),
        '30d': new Date(now - 30 * 24 * 3600 * 1000),
    };
    const from = ranges[state.timeRange] || ranges['24h'];
    return {
        from: from.toISOString(),
        to: now.toISOString(),
    };
}

function getInterval() {
    const intervals = {
        '1h': '5m',
        '6h': '30m',
        '24h': '1h',
        '7d': '6h',
        '30d': '1d',
    };
    return intervals[state.timeRange] || '1h';
}

async function apiFetch(endpoint, options = {}) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            ...options,
            headers: { 'Content-Type': 'application/json', ...options.headers },
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error(`API Error [${endpoint}]:`, error);
        return null;
    }
}

// Debounce helper
function debounce(fn, ms) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), ms);
    };
}

// ═══════════════════════════════════════════════════════════════
//  Tab Navigation
// ═══════════════════════════════════════════════════════════════

function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const tabContents = document.querySelectorAll('.tab-content');
    const pageTitle = document.getElementById('page-title');

    const titles = {
        dashboard: 'Dashboard',
        search: 'Tìm kiếm Log',
        livefeed: 'Live Feed',
        alerts: 'Cảnh báo',
        system: 'Hệ thống',
    };

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const tab = item.dataset.tab;
            if (tab === state.currentTab) return;

            // Update nav
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            // Update content
            tabContents.forEach(t => t.classList.remove('active'));
            const target = document.getElementById(`tab-${tab}`);
            if (target) target.classList.add('active');

            // Update title
            pageTitle.textContent = titles[tab] || 'Dashboard';
            state.currentTab = tab;

            // Trigger data load based on tab
            if (tab === 'dashboard') loadDashboard();
            if (tab === 'system') loadSystemInfo();
            if (tab === 'livefeed') loadLiveFeed();
            if (tab === 'alerts') loadAlerts();
        });
    });

    // Menu toggle
    const menuToggle = document.getElementById('menu-toggle');
    const sidebar = document.getElementById('sidebar');
    menuToggle.addEventListener('click', () => {
        sidebar.classList.toggle('open');
    });

    // Close sidebar on click outside (mobile)
    document.addEventListener('click', (e) => {
        if (window.innerWidth <= 768 &&
            sidebar.classList.contains('open') &&
            !sidebar.contains(e.target) &&
            !menuToggle.contains(e.target)) {
            sidebar.classList.remove('open');
        }
    });
}

// ═══════════════════════════════════════════════════════════════
//  Time Range Selector
// ═══════════════════════════════════════════════════════════════

function initTimeRange() {
    const buttons = document.querySelectorAll('.time-btn');
    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            buttons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.timeRange = btn.dataset.range;
            loadDashboard();
        });
    });
}

// ═══════════════════════════════════════════════════════════════
//  Dashboard - Stats & Charts
// ═══════════════════════════════════════════════════════════════

async function loadDashboard() {
    const { from, to } = getTimeRange();
    const interval = getInterval();

    const refreshBtn = document.getElementById('refresh-btn');
    refreshBtn.classList.add('spinning');

    const data = await apiFetch(`/stats?time_from=${from}&time_to=${to}&interval=${interval}`);

    refreshBtn.classList.remove('spinning');

    if (!data || data.status !== 'success') {
        console.warn('Failed to load stats');
        return;
    }

    // Update stat cards
    document.getElementById('stat-total-logs').textContent = formatNumber(data.summary.total_logs);
    document.getElementById('stat-attacks').textContent = formatNumber(data.summary.total_attacks);
    document.getElementById('stat-unique-ips').textContent = formatNumber(data.summary.unique_ips);
    document.getElementById('stat-avg-severity').textContent = data.summary.avg_severity.toFixed(1);

    // Update subtitle
    document.getElementById('timeline-subtitle').textContent = `Latency: ${data.query_latency_ms}ms`;

    // Render charts
    renderTimelineChart(data.timeline);
    renderEventTypesChart(data.event_types);
    renderTopIPsChart(data.top_attackers);
    renderSeverityChart(data.severity_breakdown);
    renderSourcesChart(data.source_distribution);
    renderAttackPatternsChart(data.attack_patterns);
}

// ─── Chart: Timeline ───
function renderTimelineChart(timelineData) {
    const ctx = document.getElementById('chart-timeline');
    if (state.charts.timeline) state.charts.timeline.destroy();

    const labels = timelineData.map(t => t.time);
    const totalData = timelineData.map(t => t.total);
    const attackData = timelineData.map(t => t.attacks);

    state.charts.timeline = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [
                {
                    label: 'Tổng Log',
                    data: totalData,
                    borderColor: COLORS.blue,
                    backgroundColor: 'rgba(59, 130, 246, 0.08)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                    pointHoverRadius: 5,
                    borderWidth: 2,
                },
                {
                    label: 'Attacks',
                    data: attackData,
                    borderColor: COLORS.red,
                    backgroundColor: 'rgba(239, 68, 68, 0.08)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                    pointHoverRadius: 5,
                    borderWidth: 2,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: { labels: { ...CHART_LEGEND_LABELS, padding: 16 } },
                tooltip: CHART_TOOLTIP,
            },
            scales: {
                x: {
                    grid: { color: CHART_GRID_COLOR },
                    ticks: {
                        ...CHART_TICK_STYLE,
                        maxTicksLimit: 10,
                        maxRotation: 0,
                        callback: function(value, index) {
                            const label = this.getLabelForValue(value);
                            try {
                                const d = new Date(label);
                                return d.toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' });
                            } catch { return label; }
                        }
                    },
                },
                y: {
                    grid: { color: CHART_GRID_COLOR },
                    ticks: CHART_TICK_STYLE,
                    beginAtZero: true,
                },
            },
        },
    });
}

// ─── Chart: Event Types ───
function renderEventTypesChart(eventTypes) {
    const ctx = document.getElementById('chart-event-types');
    if (state.charts.eventTypes) state.charts.eventTypes.destroy();

    state.charts.eventTypes = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: eventTypes.map(e => e.name),
            datasets: [{
                data: eventTypes.map(e => e.count),
                backgroundColor: CHART_PALETTE.slice(0, eventTypes.length),
                borderWidth: 0,
                hoverOffset: 8,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: { position: 'right', labels: { ...CHART_LEGEND_LABELS, pointStyleWidth: 10 } },
                tooltip: CHART_TOOLTIP,
            },
        },
    });
}

// ─── Chart: Top IPs ───
function renderTopIPsChart(attackers) {
    const ctx = document.getElementById('chart-top-ips');
    if (state.charts.topIPs) state.charts.topIPs.destroy();

    state.charts.topIPs = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: attackers.map(a => a.ip),
            datasets: [{
                label: 'Attacks',
                data: attackers.map(a => a.count),
                backgroundColor: attackers.map((_, i) => {
                    const opacity = 1 - (i * 0.07);
                    return `rgba(239, 68, 68, ${opacity})`;
                }),
                borderRadius: 6,
                borderSkipped: false,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: { display: false },
                tooltip: CHART_TOOLTIP,
            },
            scales: {
                x: {
                    grid: { color: CHART_GRID_COLOR },
                    ticks: { ...CHART_TICK_STYLE },
                    beginAtZero: true,
                },
                y: {
                    grid: { display: false },
                    ticks: {
                        color: '#06b6d4',
                        font: { size: 11, family: "'Courier New', monospace" },
                    },
                },
            },
        },
    });
}

// ─── Chart: Severity ───
function renderSeverityChart(severityData) {
    const ctx = document.getElementById('chart-severity');
    if (state.charts.severity) state.charts.severity.destroy();

    const severityColors = {
        1: '#6b7280',
        2: '#3b82f6',
        3: '#eab308',
        4: '#f59e0b',
        5: '#ef4444',
    };

    const severityLabels = {
        1: 'Info (1)',
        2: 'Low (2)',
        3: 'Medium (3)',
        4: 'High (4)',
        5: 'Critical (5)',
    };

    state.charts.severity = new Chart(ctx, {
        type: 'polarArea',
        data: {
            labels: severityData.map(s => severityLabels[s.level] || `Level ${s.level}`),
            datasets: [{
                data: severityData.map(s => s.count),
                backgroundColor: severityData.map(s => {
                    const c = severityColors[s.level] || '#6b7280';
                    return c + '66';
                }),
                borderColor: severityData.map(s => severityColors[s.level] || '#6b7280'),
                borderWidth: 2,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: CHART_LEGEND_LABELS },
                tooltip: CHART_TOOLTIP,
            },
            scales: {
                r: {
                    grid: { color: CHART_GRID_COLOR },
                    ticks: { display: false },
                },
            },
        },
    });
}

// ─── Chart: Sources ───
function renderSourcesChart(sourceData) {
    const ctx = document.getElementById('chart-sources');
    if (state.charts.sources) state.charts.sources.destroy();

    const sourceColors = {
        'web_server': COLORS.blue,
        'firewall': COLORS.orange,
        'ids': COLORS.purple,
        'unknown': COLORS.teal,
    };

    state.charts.sources = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: sourceData.map(s => s.source),
            datasets: [{
                data: sourceData.map(s => s.count),
                backgroundColor: sourceData.map(s => (sourceColors[s.source] || COLORS.teal) + '99'),
                borderColor: sourceData.map(s => sourceColors[s.source] || COLORS.teal),
                borderWidth: 2,
                hoverOffset: 8,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: { position: 'right', labels: CHART_LEGEND_LABELS },
                tooltip: CHART_TOOLTIP,
            },
        },
    });
}

// ─── Chart: Attack Patterns ───
function renderAttackPatternsChart(patternData) {
    const ctx = document.getElementById('chart-attack-patterns');
    const emptyHint = document.getElementById('attack-patterns-empty');
    if (!patternData || patternData.length === 0) {
        if (state.charts.attackPatterns) {
            state.charts.attackPatterns.destroy();
            state.charts.attackPatterns = null;
        }
        if (emptyHint) emptyHint.hidden = false;
        if (ctx) ctx.style.display = 'none';
        return;
    }
    if (emptyHint) emptyHint.hidden = true;
    if (ctx) ctx.style.display = 'block';

    if (state.charts.attackPatterns) state.charts.attackPatterns.destroy();

    state.charts.attackPatterns = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: patternData.map(p => p.pattern.replace('_', ' ').toUpperCase()),
            datasets: [{
                label: 'Occurrences',
                data: patternData.map(p => p.count),
                backgroundColor: CHART_PALETTE.slice(0, patternData.length).map(c => c + '88'),
                borderColor: CHART_PALETTE.slice(0, patternData.length),
                borderWidth: 1.5,
                borderRadius: 6,
                borderSkipped: false,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { ...CHART_TICK_STYLE, maxRotation: 45 },
                },
                y: {
                    grid: { color: CHART_GRID_COLOR },
                    ticks: CHART_TICK_STYLE,
                    beginAtZero: true,
                },
            },
        },
    });
}

// ═══════════════════════════════════════════════════════════════
//  Search
// ═══════════════════════════════════════════════════════════════

function initSearch() {
    const btnSearch = document.getElementById('btn-search');
    const btnClear = document.getElementById('btn-clear-search');
    const inputQuery = document.getElementById('search-query');

    btnSearch.addEventListener('click', () => {
        state.searchPage = 1;
        performSearch();
    });

    btnClear.addEventListener('click', clearSearchFilters);

    // Enter key triggers search
    document.querySelectorAll('#tab-search .filter-input, #tab-search .filter-select').forEach(el => {
        el.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                state.searchPage = 1;
                performSearch();
            }
        });
    });

    // Debounced search for query input
    inputQuery.addEventListener('input', debounce(() => {
        if (inputQuery.value.length >= 3 || inputQuery.value.length === 0) {
            state.searchPage = 1;
            performSearch();
        }
    }, 500));
}

function clearSearchFilters() {
    document.getElementById('search-query').value = '';
    document.getElementById('search-ip').value = '';
    document.getElementById('search-event-type').value = '';
    document.getElementById('search-source').value = '';
    document.getElementById('search-severity-min').value = '';
    document.getElementById('search-attacks-only').value = '';
    document.getElementById('search-time-from').value = '';
    document.getElementById('search-time-to').value = '';

    document.getElementById('search-result-count').textContent = 'Chưa tìm kiếm';
    document.getElementById('search-latency').textContent = '';
    document.getElementById('search-results-body').innerHTML =
        '<tr><td colspan="7" class="empty-state">Nhập bộ lọc và nhấn "Tìm kiếm" để bắt đầu</td></tr>';
    document.getElementById('search-pagination').innerHTML = '';
}

async function performSearch() {
    const params = new URLSearchParams();

    const q = document.getElementById('search-query').value.trim();
    const ip = document.getElementById('search-ip').value.trim();
    const eventType = document.getElementById('search-event-type').value;
    const source = document.getElementById('search-source').value;
    const severityMin = document.getElementById('search-severity-min').value;
    const attacksOnly = document.getElementById('search-attacks-only').value;
    const timeFrom = document.getElementById('search-time-from').value;
    const timeTo = document.getElementById('search-time-to').value;

    if (q) params.set('q', q);
    if (ip) params.set('src_ip', ip);
    if (eventType) params.set('event_type', eventType);
    if (source) params.set('source', source);
    if (severityMin) params.set('severity_min', severityMin);
    if (attacksOnly) params.set('is_attack', attacksOnly);
    if (timeFrom) params.set('time_from', new Date(timeFrom).toISOString());
    if (timeTo) params.set('time_to', new Date(timeTo).toISOString());

    params.set('page', state.searchPage);
    params.set('size', state.searchSize);

    const countEl = document.getElementById('search-result-count');
    const latencyEl = document.getElementById('search-latency');
    countEl.textContent = 'Đang tìm kiếm...';

    const data = await apiFetch(`/search?${params.toString()}`);

    if (!data || data.status !== 'success') {
        countEl.textContent = 'Lỗi khi tìm kiếm';
        latencyEl.textContent = '';
        return;
    }

    countEl.textContent = `Tìm thấy ${formatNumber(data.total)} kết quả (trang ${data.page}/${data.total_pages || 1})`;
    latencyEl.textContent = `Query: ${data.query_latency_ms}ms`;

    renderSearchResults(data.results);
    renderPagination(data.total, data.page, data.total_pages);
}

function renderSearchResults(results) {
    const tbody = document.getElementById('search-results-body');

    if (!results || results.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Không tìm thấy kết quả</td></tr>';
        return;
    }

    tbody.innerHTML = results.map(log => {
        const severity = log.severity || 0;
        const isAttack = log.is_attack;
        return `
            <tr>
                <td>${formatTimestamp(log.timestamp || log['@timestamp'])}</td>
                <td><span class="log-event">${log.event_type || '—'}</span></td>
                <td><span class="log-ip">${log.src_ip || '—'}</span></td>
                <td><span class="severity-badge severity-${severity}">${severity}</span></td>
                <td>${log.source || '—'}</td>
                <td title="${(log.message || log.log_message || '').replace(/"/g, '&quot;')}">${log.message || log.log_message || '—'}</td>
                <td><span class="attack-badge ${isAttack ? 'yes' : 'no'}">${isAttack ? 'ATTACK' : 'OK'}</span></td>
            </tr>
        `;
    }).join('');
}

function renderPagination(total, currentPage, totalPages) {
    const container = document.getElementById('search-pagination');
    if (totalPages <= 1) {
        container.innerHTML = '';
        return;
    }

    let html = '';

    // Prev
    html += `<button class="page-btn" ${currentPage <= 1 ? 'disabled' : ''} data-page="${currentPage - 1}">‹</button>`;

    // Page numbers
    const maxVisible = 5;
    let startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
    let endPage = Math.min(totalPages, startPage + maxVisible - 1);
    if (endPage - startPage < maxVisible - 1) {
        startPage = Math.max(1, endPage - maxVisible + 1);
    }

    if (startPage > 1) {
        html += `<button class="page-btn" data-page="1">1</button>`;
        if (startPage > 2) html += `<span style="color: var(--text-muted); padding: 0 4px;">...</span>`;
    }

    for (let i = startPage; i <= endPage; i++) {
        html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) html += `<span style="color: var(--text-muted); padding: 0 4px;">...</span>`;
        html += `<button class="page-btn" data-page="${totalPages}">${totalPages}</button>`;
    }

    // Next
    html += `<button class="page-btn" ${currentPage >= totalPages ? 'disabled' : ''} data-page="${currentPage + 1}">›</button>`;

    container.innerHTML = html;

    // Bind events
    container.querySelectorAll('.page-btn:not(:disabled)').forEach(btn => {
        btn.addEventListener('click', () => {
            state.searchPage = parseInt(btn.dataset.page);
            performSearch();
        });
    });
}

// ═══════════════════════════════════════════════════════════════
//  Live Feed
// ═══════════════════════════════════════════════════════════════

function initLiveFeed() {
    const toggleBtn = document.getElementById('btn-livefeed-toggle');
    toggleBtn.addEventListener('click', () => {
        state.liveFeedActive = !state.liveFeedActive;
        toggleBtn.classList.toggle('paused', !state.liveFeedActive);

        if (state.liveFeedActive) {
            loadLiveFeed();
            startLiveFeedPolling();
        } else {
            stopLiveFeedPolling();
        }
    });
}

async function loadLiveFeed() {
    const limit = document.getElementById('livefeed-limit').value || 50;
    const statusEl = document.getElementById('livefeed-status');

    statusEl.textContent = 'Đang tải...';
    const data = await apiFetch(`/recent?limit=${limit}`);

    if (!data || data.status !== 'success') {
        statusEl.textContent = 'Lỗi kết nối API';
        return;
    }

    statusEl.textContent = `${data.count} log mới nhất • Cập nhật lúc ${new Date().toLocaleTimeString('vi-VN')}`;
    renderLiveFeed(data.results);
}

function renderLiveFeed(logs) {
    const stream = document.getElementById('livefeed-stream');

    if (!logs || logs.length === 0) {
        stream.innerHTML = '<div class="empty-state" style="padding: 60px; text-align: center; color: var(--text-muted);">Chưa có log nào</div>';
        return;
    }

    stream.innerHTML = logs.map(log => {
        const isAttack = log.is_attack;
        const severity = log.severity || 0;
        return `
            <div class="log-entry ${isAttack ? 'attack' : 'normal'}">
                <span class="log-time">${formatTimestamp(log.timestamp || log['@timestamp'])}</span>
                <span class="log-event" style="color: ${isAttack ? COLORS.red : COLORS.green}">${log.event_type || '—'}</span>
                <span class="log-ip">${log.src_ip || '—'}</span>
                <span class="severity-badge severity-${severity}">${severity}</span>
                <span class="log-msg">${log.message || log.log_message || '—'}</span>
            </div>
        `;
    }).join('');
}

function startLiveFeedPolling() {
    stopLiveFeedPolling();
    state.intervals.livefeed = setInterval(() => {
        if (state.currentTab === 'livefeed' && state.liveFeedActive) {
            loadLiveFeed();
        }
    }, LIVEFEED_INTERVAL);
}

function stopLiveFeedPolling() {
    if (state.intervals.livefeed) {
        clearInterval(state.intervals.livefeed);
        state.intervals.livefeed = null;
    }
}

// ═══════════════════════════════════════════════════════════════
//  Alerts
// ═══════════════════════════════════════════════════════════════

function initAlerts() {
    const btnRefresh = document.getElementById('btn-refresh-alerts');
    const filterStatus = document.getElementById('alert-status-filter');

    if (btnRefresh) {
        btnRefresh.addEventListener('click', loadAlerts);
    }
    
    if (filterStatus) {
        filterStatus.addEventListener('change', loadAlerts);
    }

    // Auto update alert badge
    setInterval(updateAlertBadge, 15000);
    updateAlertBadge();
}

async function updateAlertBadge() {
    const data = await apiFetch('/alerts?status=pending&size=1');
    const badge = document.getElementById('nav-alert-badge');
    if (badge && data && data.status === 'success') {
        const count = data.total;
        badge.textContent = count > 99 ? '99+' : count;
        badge.style.display = count > 0 ? 'inline-flex' : 'none';
    }
}

async function loadAlerts() {
    const status = document.getElementById('alert-status-filter').value;
    const countEl = document.getElementById('alerts-count');
    
    countEl.textContent = 'Đang tải...';
    
    let url = '/alerts?size=50';
    if (status) {
        url += `&status=${status}`;
    }

    const data = await apiFetch(url);

    if (!data || data.status !== 'success') {
        countEl.textContent = 'Lỗi kết nối API';
        return;
    }

    countEl.textContent = `Tìm thấy ${data.total} cảnh báo`;
    renderAlerts(data.results);
}

function renderAlerts(alerts) {
    const tbody = document.getElementById('alerts-body');

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Không có cảnh báo nào</td></tr>';
        return;
    }

    tbody.innerHTML = alerts.map(alert => {
        let statusClass = alert.status;
        let statusText = alert.status.toUpperCase();
        
        let actionBtn = '';
        if (alert.status === 'pending' || alert.status === 'investigating') {
            actionBtn = `<button class="btn-resolve" onclick="resolveAlert('${alert._id}')">Đánh dấu đã xử lý</button>`;
        } else {
            actionBtn = `<span style="color: var(--text-muted);">Đã xử lý</span>`;
        }

        return `
            <tr>
                <td>${formatTimestamp(alert.timestamp)}</td>
                <td><span class="status-badge status-${statusClass}">${statusText}</span></td>
                <td><span class="log-ip">${alert.src_ip}</span></td>
                <td><span class="log-event">${alert.event_type}</span></td>
                <td><span class="severity-badge severity-${alert.severity === 'high' ? '5' : '3'}">${alert.severity}</span></td>
                <td>${alert.related_logs}</td>
                <td>${alert.message}</td>
                <td>${actionBtn}</td>
            </tr>
        `;
    }).join('');
}

window.resolveAlert = async function(alertId) {
    if (!confirm('Xác nhận đánh dấu cảnh báo này là đã xử lý?')) return;
    
    const res = await apiFetch(`/alerts/${alertId}`, {
        method: 'PATCH',
        body: JSON.stringify({ status: 'resolved' })
    });
    
    if (res && res.status === 'success') {
        loadAlerts();
        updateAlertBadge();
    } else {
        alert('Lỗi cập nhật cảnh báo');
    }
}

// ═══════════════════════════════════════════════════════════════
//  System Info
// ═══════════════════════════════════════════════════════════════

async function loadSystemInfo() {
    // Health
    const health = await apiFetch('/health');
    if (health) {
        setStatusBadge('sys-api', health.api);
        setStatusBadge('sys-redis', health.redis);
        setStatusBadge('sys-es', health.elasticsearch);
        document.getElementById('sys-es-ver').textContent = health.es_version || '—';
        document.getElementById('sys-total-indexed').textContent = formatNumber(health.total_indexed_logs || 0);
        document.getElementById('sys-index-size').textContent = `${health.index_size_mb || 0} MB`;
        document.getElementById('sys-queue-len').textContent = formatNumber(health.redis_queue_length || 0);

        // Update sidebar status
        const statusDot = document.querySelector('.system-status .status-dot');
        const statusText = document.querySelector('.system-status span');
        if (health.overall === 'ok') {
            statusDot.className = 'status-dot ok';
            statusText.textContent = 'Hệ thống hoạt động';
        } else {
            statusDot.className = 'status-dot error';
            statusText.textContent = 'Hệ thống lỗi';
        }
    }

    // Metrics
    const metrics = await apiFetch('/metrics');
    if (metrics && metrics.status === 'success') {
        document.getElementById('sys-uptime').textContent = formatUptime(metrics.uptime_seconds || 0);
        document.getElementById('sys-ingested').textContent = formatNumber(metrics.total_ingested || 0);
        document.getElementById('sys-queries').textContent = formatNumber(metrics.total_queries || 0);
        document.getElementById('sys-ingest-rate').textContent = `${metrics.avg_ingest_rate_per_second || 0} logs/s`;
        document.getElementById('sys-batch-rate').textContent = `${metrics.last_batch_ingest_rate || 0} logs/s`;
        document.getElementById('sys-query-latency').textContent = `${metrics.last_query_latency_ms || 0} ms`;
    }
}

function setStatusBadge(id, status) {
    const el = document.getElementById(id);
    el.textContent = status || '—';
    el.className = `status-badge ${status || 'unknown'}`;
}

// ═══════════════════════════════════════════════════════════════
//  Auto Refresh
// ═══════════════════════════════════════════════════════════════

function startAutoRefresh() {
    stopAutoRefresh();
    state.intervals.autoRefresh = setInterval(() => {
        if (!state.autoRefresh) return;
        if (state.currentTab === 'dashboard') loadDashboard();
        if (state.currentTab === 'system') loadSystemInfo();
    }, REFRESH_INTERVAL);
}

function stopAutoRefresh() {
    if (state.intervals.autoRefresh) {
        clearInterval(state.intervals.autoRefresh);
        state.intervals.autoRefresh = null;
    }
}

// ═══════════════════════════════════════════════════════════════
//  Refresh Button
// ═══════════════════════════════════════════════════════════════

function initRefreshBtn() {
    const tabLoaders = {
        dashboard: loadDashboard,
        search: performSearch,
        livefeed: loadLiveFeed,
        system: loadSystemInfo,
    };
    document.getElementById('refresh-btn').addEventListener('click', () => {
        tabLoaders[state.currentTab]?.();
    });
}

// ═══════════════════════════════════════════════════════════════
//  Init
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    // Set Chart.js defaults
    Chart.defaults.font.family = 'Inter';

    initNavigation();
    initTimeRange();
    initSearch();
    initLiveFeed();
    initAlerts();
    initRefreshBtn();

    // Initial load
    loadDashboard();
    loadSystemInfo();

    // Start polling
    startAutoRefresh();
    startLiveFeedPolling();
});
