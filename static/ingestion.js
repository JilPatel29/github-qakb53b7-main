let _ingestionRunning = false;
let _ingestionInterval = 30;
let _countdownTimer = null;
let _countdownRemaining = 0;
let _statusPollTimer = null;
let _tableRefreshTimer = null;

function initIngestionPanel() {
    const startBtn = document.getElementById('startIngestionBtn');
    const stopBtn = document.getElementById('stopIngestionBtn');

    startBtn.addEventListener('click', handleStart);
    stopBtn.addEventListener('click', handleStop);

    fetch('/api/ingestion/status')
        .then(r => r.json())
        .then(data => {
            applyStatus(data);
            if (data.running) {
                _ingestionRunning = true;
                _ingestionInterval = data.interval;
                startCountdown(data.interval);
                startStatusPolling();
            }
        })
        .catch(() => {});
}

async function handleStart() {
    const intervalInput = document.getElementById('scanInterval');
    const interval = Math.max(10, parseInt(intervalInput.value) || 30);
    intervalInput.value = interval;

    const startBtn = document.getElementById('startIngestionBtn');
    const stopBtn = document.getElementById('stopIngestionBtn');
    startBtn.disabled = true;

    try {
        const res = await fetch('/api/ingestion/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interval })
        });
        const data = await res.json();
        if (data.success) {
            _ingestionRunning = true;
            _ingestionInterval = interval;
            startBtn.disabled = true;
            stopBtn.disabled = false;
            setStatusRunning(true);
            startCountdown(interval);
            startStatusPolling();
            startTableAutoRefresh();
        } else {
            startBtn.disabled = false;
        }
    } catch (e) {
        startBtn.disabled = false;
    }
}

async function handleStop() {
    const startBtn = document.getElementById('startIngestionBtn');
    const stopBtn = document.getElementById('stopIngestionBtn');
    stopBtn.disabled = true;

    try {
        await fetch('/api/ingestion/stop', { method: 'POST' });
    } catch (e) {}

    _ingestionRunning = false;
    startBtn.disabled = false;
    stopBtn.disabled = true;
    setStatusRunning(false);
    stopCountdown();
    stopStatusPolling();
    stopTableAutoRefresh();

    document.getElementById('nextScanIn').textContent = '-';
    const wrap = document.getElementById('countdownWrap');
    if (wrap) wrap.style.display = 'none';
}

function setStatusRunning(running) {
    const dot = document.getElementById('statusDot');
    const text = document.getElementById('statusText');
    if (!dot || !text) return;
    if (running) {
        dot.className = 'status-dot running';
        text.textContent = 'Running';
    } else {
        dot.className = 'status-dot';
        text.textContent = 'Stopped';
    }
}

function applyStatus(data) {
    setStatusRunning(data.running);

    const scanCountEl = document.getElementById('scanCount');
    if (scanCountEl) scanCountEl.textContent = data.scan_count || 0;

    const lastScanEl = document.getElementById('lastScan');
    if (lastScanEl) lastScanEl.textContent = data.last_scan || 'Never';

    if (data.log && data.log.length > 0) {
        renderActivityLog(data.log);
    }

    const startBtn = document.getElementById('startIngestionBtn');
    const stopBtn = document.getElementById('stopIngestionBtn');
    if (startBtn) startBtn.disabled = data.running;
    if (stopBtn) stopBtn.disabled = !data.running;
}

function renderActivityLog(logEntries) {
    const container = document.getElementById('activityLog');
    if (!container) return;

    if (!logEntries || logEntries.length === 0) {
        container.innerHTML = '<div class="log-empty">No activity yet. Press Start Auto-Ingest to begin.</div>';
        return;
    }

    container.innerHTML = logEntries.map(entry => `
        <div class="log-entry ${entry.status || ''}">
            <span class="log-time">${entry.time || ''}</span>
            <span class="log-msg">${escapeHtml(entry.msg || '')}</span>
        </div>
    `).join('');
}

function startCountdown(interval) {
    stopCountdown();
    _countdownRemaining = interval;

    const wrap = document.getElementById('countdownWrap');
    if (wrap) wrap.style.display = 'block';

    _countdownTimer = setInterval(() => {
        if (!_ingestionRunning) {
            stopCountdown();
            return;
        }
        _countdownRemaining--;
        if (_countdownRemaining <= 0) {
            _countdownRemaining = _ingestionInterval;
        }
        updateCountdownUI(_countdownRemaining, _ingestionInterval);
    }, 1000);

    updateCountdownUI(_countdownRemaining, interval);
}

function stopCountdown() {
    if (_countdownTimer) {
        clearInterval(_countdownTimer);
        _countdownTimer = null;
    }
    const fill = document.getElementById('countdownFill');
    if (fill) fill.style.width = '0%';
}

function updateCountdownUI(remaining, total) {
    const nextEl = document.getElementById('nextScanIn');
    if (nextEl) nextEl.textContent = `${remaining}s`;

    const fill = document.getElementById('countdownFill');
    if (fill) {
        const pct = ((total - remaining) / total) * 100;
        fill.style.width = pct + '%';
    }
}

function startStatusPolling() {
    stopStatusPolling();
    _statusPollTimer = setInterval(async () => {
        if (!_ingestionRunning) return;
        try {
            const res = await fetch('/api/ingestion/status');
            const data = await res.json();
            const scanCountEl = document.getElementById('scanCount');
            if (scanCountEl) scanCountEl.textContent = data.scan_count || 0;
            const lastScanEl = document.getElementById('lastScan');
            if (lastScanEl) lastScanEl.textContent = data.last_scan || 'Never';
            if (data.log && data.log.length > 0) {
                renderActivityLog(data.log);
            }
            if (data.next_scan_in != null && _ingestionRunning) {
                _countdownRemaining = data.next_scan_in;
                updateCountdownUI(_countdownRemaining, _ingestionInterval);
            }
            if (!data.running && _ingestionRunning) {
                _ingestionRunning = false;
                setStatusRunning(false);
                stopCountdown();
                stopStatusPolling();
                stopTableAutoRefresh();
                document.getElementById('startIngestionBtn').disabled = false;
                document.getElementById('stopIngestionBtn').disabled = true;
            }
        } catch (e) {}
    }, 2000);
}

function stopStatusPolling() {
    if (_statusPollTimer) {
        clearInterval(_statusPollTimer);
        _statusPollTimer = null;
    }
}

function startTableAutoRefresh() {
    stopTableAutoRefresh();
    _tableRefreshTimer = setInterval(() => {
        if (!_ingestionRunning) return;
        if (typeof loadLogs === 'function') loadLogs();
    }, 15000);
}

function stopTableAutoRefresh() {
    if (_tableRefreshTimer) {
        clearInterval(_tableRefreshTimer);
        _tableRefreshTimer = null;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
