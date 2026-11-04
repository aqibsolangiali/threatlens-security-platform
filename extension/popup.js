const urlBox = document.querySelector('#url'), button = document.querySelector('#check'), resultBox = document.querySelector('#result'), message = document.querySelector('#message');
let tabUrl = '';
chrome.tabs.query({active:true,currentWindow:true}, tabs => {
  tabUrl = tabs[0]?.url || '';
  urlBox.textContent = tabUrl || 'This tab URL is unavailable.';
  if (!/^https?:\/\//i.test(tabUrl)) {
    urlBox.classList.add('warning'); button.disabled = true;
    message.textContent = 'Only regular HTTP and HTTPS website tabs can be checked.';
  }
});
button.addEventListener('click', async () => {
  button.disabled = true; button.firstChild.textContent = 'Checking… '; resultBox.classList.add('hidden');
  try {
    const response = await fetch('http://127.0.0.1:8000/api/scan', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:tabUrl})});
    const data = await response.json(); if (!response.ok) throw new Error(data.detail || 'The check failed.');
    resultBox.replaceChildren(); resultBox.classList.remove('hidden');
    const title = document.createElement('strong'), tag = document.createElement('span'), details = document.createElement('p');
    title.textContent = data.domain; tag.className = `tag ${data.level}`; tag.textContent = `${data.score}/100 · ${data.level.toUpperCase()}`; title.append(tag);
    details.textContent = data.findings.map(f => `${f.title}: ${f.detail}`).join(' '); resultBox.append(title, details);
    message.textContent = 'Review these signals before deciding whether to continue.';
  } catch (e) {
    resultBox.replaceChildren(); resultBox.classList.remove('hidden');
    const title = document.createElement('strong'), details = document.createElement('p');
    title.textContent = 'Could not reach ThreatLens'; details.textContent = `${e.message}. Start the local app, then try again.`; resultBox.append(title, details);
  } finally { button.disabled = false; button.firstChild.textContent = 'Analyze this link '; }
});
