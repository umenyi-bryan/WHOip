const fileInput = document.getElementById('file');
const main = document.getElementById('main');

fileInput.addEventListener('change', e => {
  const f = e.target.files[0];
  if (!f) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const j = JSON.parse(reader.result);
      renderReport(j);
    } catch (err) {
      main.innerHTML = `<div class="panel">Failed to parse JSON: ${err}</div>`;
    }
  };
  reader.readAsText(f);
});

function renderReport(r) {
  const parts = [];
  parts.push(`<div class="panel file-info"><span class="k">Target:</span> ${escapeHtml(r.target || '')} <span style="margin-left:12px" class="k">Generated:</span> ${escapeHtml(r.generated_at||'')}</div>`);
  const keys = ['resolved_ip','geo','rdns','whois','nmap','banners','http','tls','shodan'];
  keys.forEach(k => {
    if (r[k]) {
      parts.push(`<div class="panel"><h3>${k.toUpperCase()}</h3><pre>${escapeHtml(JSON.stringify(r[k], null, 2))}</pre></div>`);
    }
  });
  main.innerHTML = parts.join('\n');
}

function escapeHtml(s){
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#039;');
}
