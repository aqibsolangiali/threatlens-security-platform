const $ = (s) => document.querySelector(s);
const form = $('#scanForm'), input = $('#urlInput'), button = $('#scanButton'), resultBox = $('#result');
const escapeHtml = (value) => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function when(value) { const d = new Date(value); return Number.isNaN(+d) ? 'Recently' : d.toLocaleString([], {month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}); }
async function refresh() {
  const [statsRes, historyRes] = await Promise.all([fetch('/api/stats'), fetch('/api/history?limit=8')]);
  const stats = await statsRes.json(), items = await historyRes.json();
  $('#totalScans').textContent = stats.total_scans; $('#highScans').textContent = stats.high_risk; $('#cautionScans').textContent = stats.caution;
  const body = $('#historyBody');
  body.innerHTML = items.length ? items.map(x => `<tr><td>${escapeHtml(x.domain)}</td><td><span class="badge ${escapeHtml(x.level)}">${x.level === 'high' ? 'Higher concern' : x.level === 'medium' ? 'Use caution' : 'Fewer signals'}</span></td><td class="score-cell">${x.score}/100</td><td class="time-cell">${escapeHtml(when(x.created_at))}</td></tr>`).join('') : '<tr><td colspan="4" class="empty">Your recent checks will appear here.</td></tr>';
}
function renderResult(data) {
  resultBox.classList.remove('hidden');
  const findings = data.findings.map(f => `<div class="finding"><span class="finding-mark ${escapeHtml(f.severity)}">${f.severity === 'good' ? '✓' : '!'}</span><span><b>${escapeHtml(f.title)}:</b> ${escapeHtml(f.detail)}</span></div>`).join('');
  let page = '';
  if (data.page_inspection) {
    const p = data.page_inspection;
    const title = p.title ? `<p><b>Page title:</b> ${escapeHtml(p.title)}</p>` : '';
    const description = p.description ? `<p><b>Page description:</b> ${escapeHtml(p.description)}</p>` : '';
    const excerpt = p.excerpt ? `<p class="page-excerpt"><b>Visible text preview:</b><br>${escapeHtml(p.excerpt)}</p>` : '';
    const finalDomain = p.final_domain ? `<p><b>Redirected to:</b> ${escapeHtml(p.final_domain)}</p>` : '';
    page = `<section class="page-inspection"><h3>${p.status === 'inspected' ? 'What the page says' : 'Page inspection'}</h3>${title}${description}${excerpt}${finalDomain}<p class="inspection-status">${escapeHtml(p.message)}</p></section>`;
  }
  resultBox.innerHTML = `<div class="result-top"><div class="result-domain">${escapeHtml(data.domain)}</div><span class="result-score ${escapeHtml(data.level)}">${data.score} / 100</span></div><div class="result-label">${escapeHtml(data.label)}</div>${findings}${page}`;
}
form.addEventListener('submit', async e => {
  e.preventDefault(); button.disabled = true; button.querySelector('span').textContent = 'Checking…'; resultBox.classList.add('hidden');
  try {
    const res = await fetch('/api/scan', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:input.value,inspect_page:$('#inspectPage').checked})});
    const data = await res.json(); if (!res.ok) throw new Error(data.detail || 'Could not analyze that address.'); renderResult(data); await refresh();
  } catch (err) { resultBox.classList.remove('hidden'); resultBox.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`; }
  finally { button.disabled = false; button.querySelector('span').textContent = 'Analyze link'; }
});
$('#exampleButton').addEventListener('click', () => { input.value = 'http://secure-account-verify.example-login.com/signin'; $('#inspectPage').checked = false; input.focus(); });
$('#clearButton').addEventListener('click', async () => { if (!confirm('Clear all scan history?')) return; await fetch('/api/history', {method:'DELETE'}); resultBox.classList.add('hidden'); await refresh(); });
refresh().catch(() => { $('#historyBody').innerHTML = '<tr><td colspan="4" class="empty">Could not load history. Is the server running?</td></tr>'; });
