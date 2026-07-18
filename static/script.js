/* ==========================================================================
   AI Phishing Website Detector — script.js
   Calls the real Flask /predict endpoint (app.py), which performs actual
   DNS resolution, live reachability, SSL checks, and structural URL
   analysis server-side. No client-side guessing — every result here comes
   from the backend response.
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  initBackgroundNetwork();
  initFadeIn();
  initRipple();
  initScanForm();
});

/* ---------------------------------------------------------------------- *
 * Floating cybersecurity background
 * ---------------------------------------------------------------------- */
function initBackgroundNetwork(){
  const canvas = document.getElementById('netCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let width, height, nodes;

  function resize(){
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  }

  function createNodes(){
    const count = Math.min(70, Math.floor((width * height) / 18000));
    nodes = Array.from({ length: count }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.25,
      vy: (Math.random() - 0.5) * 0.25,
      r: Math.random() * 1.6 + 0.6
    }));
  }

  function step(){
    ctx.clearRect(0, 0, width, height);
    for (const n of nodes){
      n.x += n.vx;
      n.y += n.vy;
      if (n.x < 0 || n.x > width) n.vx *= -1;
      if (n.y < 0 || n.y > height) n.vy *= -1;
    }
    const linkDist = 130;
    for (let i = 0; i < nodes.length; i++){
      for (let j = i + 1; j < nodes.length; j++){
        const a = nodes[i], b = nodes[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < linkDist){
          ctx.strokeStyle = `rgba(51,232,255,${0.14 * (1 - dist / linkDist)})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }
    for (const n of nodes){
      ctx.fillStyle = 'rgba(120,210,255,0.55)';
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fill();
    }
    requestAnimationFrame(step);
  }

  resize();
  createNodes();
  step();
  window.addEventListener('resize', () => { resize(); createNodes(); });
}

/* ---------------------------------------------------------------------- *
 * Fade-in reveal on scroll
 * ---------------------------------------------------------------------- */
function initFadeIn(){
  const targets = document.querySelectorAll('.fade-in');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting){
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });
  targets.forEach(t => observer.observe(t));
}

/* ---------------------------------------------------------------------- *
 * Button ripple effect
 * ---------------------------------------------------------------------- */
function initRipple(){
  const btn = document.getElementById('analyzeBtn');
  if (!btn) return;
  btn.addEventListener('click', (e) => {
    const rect = btn.getBoundingClientRect();
    const ripple = document.createElement('span');
    const size = Math.max(rect.width, rect.height);
    ripple.className = 'ripple';
    ripple.style.width = ripple.style.height = `${size}px`;
    ripple.style.left = `${e.clientX - rect.left - size / 2}px`;
    ripple.style.top = `${e.clientY - rect.top - size / 2}px`;
    btn.appendChild(ripple);
    setTimeout(() => ripple.remove(), 650);
  });
}

/* ---------------------------------------------------------------------- *
 * Scan form — real backend call
 * ---------------------------------------------------------------------- */
function initScanForm(){
  const form = document.getElementById('scanForm');
  form.addEventListener('submit', handleScan);
}

async function handleScan(e){
  e.preventDefault();
  const input = document.getElementById('urlInput');
  const url = input.value.trim();
  if (!url) return;

  const btn = document.getElementById('analyzeBtn');
  const btnLabel = btn.querySelector('.btn-label');
  const btnLoader = document.getElementById('btnLoader');
  const loadingPanel = document.getElementById('loadingPanel');
  const loadingText = document.getElementById('loadingText');
  const resultCard = document.getElementById('resultCard');
  const featuresSection = document.getElementById('featuresSection');
  const errorText = document.getElementById('errorText');

  errorText.classList.add('d-none');
  btn.disabled = true;
  btnLabel.textContent = 'Analyzing…';
  btnLoader.classList.remove('d-none');
  loadingPanel.classList.remove('d-none');
  resultCard.classList.add('d-none');
  featuresSection.classList.add('d-none');

  const steps = [
    'Checking DNS resolution…',
    'Testing live reachability…',
    'Verifying SSL certificate…',
    'Scoring structural URL signals…'
  ];
  let stepIndex = 0;
  loadingText.textContent = steps[0];
  const stepTimer = setInterval(() => {
    stepIndex = (stepIndex + 1) % steps.length;
    loadingText.textContent = steps[stepIndex];
  }, 700);

  try{
    const res = await fetch('/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    const data = await res.json();

    clearInterval(stepTimer);
    loadingPanel.classList.add('d-none');
    btn.disabled = false;
    btnLabel.textContent = 'Analyze Website';
    btnLoader.classList.add('d-none');

    if (!res.ok){
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
    resultCard.classList.add('fade-in');
    featuresSection.classList.add('fade-in');
    requestAnimationFrame(() => {
      resultCard.classList.add('is-visible');
      featuresSection.classList.add('is-visible');
    });

  } catch (err){
    clearInterval(stepTimer);
    loadingPanel.classList.add('d-none');
    btn.disabled = false;
    btnLabel.textContent = 'Analyze Website';
    btnLoader.classList.add('d-none');
    errorText.textContent = 'Could not reach the server. Make sure the Flask app is running.';
    errorText.classList.remove('d-none');
  }
}

/* ---------------------------------------------------------------------- *
 * Render prediction card
 * ---------------------------------------------------------------------- */
function renderResult(data){
  const resultCard = document.getElementById('resultCard');
  const isSafe = data.label === 'legitimate';

  resultCard.classList.remove('result-safe', 'result-danger');
  resultCard.classList.add(isSafe ? 'result-safe' : 'result-danger');

  document.getElementById('resultIcon').textContent = isSafe ? '✔' : '⚠';
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

  const fill = document.getElementById('confidenceBarFill');
  fill.style.width = '0%';
  requestAnimationFrame(() => { fill.style.width = `${data.confidence}%`; });
}

/* ---------------------------------------------------------------------- *
 * Render feature grid
 * ---------------------------------------------------------------------- */
function renderFeatures(features){
  const grid = document.getElementById('featuresGrid');
  grid.innerHTML = '';
  features.forEach(f => {
    const item = document.createElement('div');
    item.className = `feature-item ${f.safe ? 'feature-ok' : 'feature-bad'}`;
    item.innerHTML = `
      <span class="feature-icon">${f.safe ? '✔' : '✖'}</span>
      <span class="feature-name">${f.name}</span>
    `;
    grid.appendChild(item);
  });
}

/* ---------------------------------------------------------------------- *
 * History table
 * ---------------------------------------------------------------------- */
function prependHistoryRow(result){
  const tbody = document.getElementById('historyTableBody');
  const emptyRow = document.getElementById('historyEmptyRow');
  if (emptyRow) emptyRow.remove();

  const isSafe = result.label === 'legitimate';
  const row = document.createElement('tr');
  row.innerHTML = `
    <td class="mono">${truncate(result.url, 42)}</td>
    <td><span class="badge-${isSafe ? 'safe' : 'danger'}">${isSafe ? 'Legitimate' : 'Phishing'}</span></td>
    <td class="mono">${result.confidence}%</td>
    <td class="mono">${result.timestamp}</td>
  `;
  tbody.prepend(row);
}

function truncate(str, max){
  return str.length > max ? str.slice(0, max - 1) + '…' : str;
}

/* ---------------------------------------------------------------------- *
 * Statistics counters (driven by real server-side totals)
 * ---------------------------------------------------------------------- */
function updateStats(stats){
  document.getElementById('statTotal').textContent = stats.total;
  document.getElementById('statLegit').textContent = stats.legit;
  document.getElementById('statPhish').textContent = stats.phish;
}
