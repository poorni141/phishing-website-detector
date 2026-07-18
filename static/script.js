// AI Phishing Website Detector — script.js
// Calls the Flask /predict endpoint (app.py) and displays the result.

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('scanForm');
  form.addEventListener('submit', handleScan);
});

async function handleScan(e) {
  e.preventDefault();

  const input = document.getElementById('urlInput');
  const url = input.value.trim();
  if (!url) return;

  const btn = document.getElementById('analyzeBtn');
  const btnText = document.getElementById('btnText');
  const btnSpinner = document.getElementById('btnSpinner');
  const loadingPanel = document.getElementById('loadingPanel');
  const resultCard = document.getElementById('resultCard');
  const featuresSection = document.getElementById('featuresSection');
  const errorText = document.getElementById('errorText');

  errorText.classList.add('d-none');
  btn.disabled = true;
  btnText.textContent = 'Analyzing...';
  btnSpinner.classList.remove('d-none');
  loadingPanel.classList.remove('d-none');
  resultCard.classList.add('d-none');
  featuresSection.classList.add('d-none');

  try {
    const res = await fetch('/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    const data = await res.json();

    loadingPanel.classList.add('d-none');
    btn.disabled = false;
    btnText.textContent = 'Analyze Website';
    btnSpinner.classList.add('d-none');

    if (!res.ok) {
      errorText.textContent = data.error || 'Something went wrong while analyzing this URL.';
      errorText.classList.remove('d-none');
      return;
    }

    const result = data.result;
    renderResult(result);
    renderFeatures(result.features);
    prependHistoryRow(result);
    updateStats(data.stats);

    resultCard.classList.remove('d-none');
    featuresSection.classList.remove('d-none');

  } catch (err) {
    loadingPanel.classList.add('d-none');
    btn.disabled = false;
    btnText.textContent = 'Analyze Website';
    btnSpinner.classList.add('d-none');
    errorText.textContent = 'Could not reach the server. Make sure the Flask app is running.';
    errorText.classList.remove('d-none');
  }
}

function renderResult(data) {
  const resultCard = document.getElementById('resultCard');
  const isSafe = data.label === 'legitimate';

  resultCard.classList.remove('result-safe', 'result-danger');
  resultCard.classList.add(isSafe ? 'result-safe' : 'result-danger');

  const icon = document.getElementById('resultIcon');
  icon.className = 'bi fs-2 me-3 ' + (isSafe ? 'bi-check-circle-fill text-success' : 'bi-exclamation-triangle-fill text-danger');

  document.getElementById('resultTitle').textContent = isSafe
    ? 'Legitimate Website'
    : 'Phishing Website Detected';
  document.getElementById('resultMessage').textContent = isSafe
    ? 'This website appears safe to visit.'
    : 'This website appears suspicious. Avoid entering personal information.';

  document.getElementById('metricPrediction').textContent = isSafe ? 'Legitimate' : 'Phishing';
  document.getElementById('metricConfidence').textContent = `${data.confidence}%`;
  document.getElementById('metricStatus').textContent = data.status;
  document.getElementById('metricRisk').textContent = data.risk_level;
  document.getElementById('metricScanTime').textContent = data.scan_time;
}

function renderFeatures(features) {
  const grid = document.getElementById('featuresGrid');
  grid.innerHTML = '';
  features.forEach(f => {
    const col = document.createElement('div');
    col.className = 'col-12 col-sm-6 col-md-4 col-lg-3';
    col.innerHTML = `
      <div class="feature-item ${f.safe ? 'feature-ok' : 'feature-bad'}">
        <i class="bi ${f.safe ? 'bi-check-circle-fill' : 'bi-x-circle-fill'}"></i>
        <span>${f.name}</span>
      </div>
    `;
    grid.appendChild(col);
  });
}

function prependHistoryRow(result) {
  const tbody = document.getElementById('historyTableBody');
  const emptyRow = document.getElementById('historyEmptyRow');
  if (emptyRow) emptyRow.remove();

  const isSafe = result.label === 'legitimate';
  const row = document.createElement('tr');
  row.innerHTML = `
    <td>${truncate(result.url, 42)}</td>
    <td><span class="badge ${isSafe ? 'bg-success' : 'bg-danger'}">${isSafe ? 'Legitimate' : 'Phishing'}</span></td>
    <td>${result.confidence}%</td>
    <td>${result.timestamp}</td>
  `;
  tbody.prepend(row);
}

function truncate(str, max) {
  return str.length > max ? str.slice(0, max - 1) + '…' : str;
}

function updateStats(stats) {
  document.getElementById('statTotal').textContent = stats.total;
  document.getElementById('statLegit').textContent = stats.legit;
  document.getElementById('statPhish').textContent = stats.phish;
}
