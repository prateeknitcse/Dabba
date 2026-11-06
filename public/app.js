'use strict';

const $ = (id) => document.getElementById(id);
const H = { 'X-Dabba': '1' }; // required by the server on every write request (CSRF guard)

function el(tag, props = {}, children = []) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of [].concat(children)) if (c) e.append(c);
  return e;
}

async function api(method, url, body) {
  const opts = { method, headers: { ...H }, credentials: 'same-origin' };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(url, opts);
  let data = {};
  try { data = await r.json(); } catch (_) { /* no body */ }
  if (r.status === 401 && url !== '/api/pair') { showPair(); throw new Error('Not paired'); }
  if (!r.ok) throw new Error(data.error || `Request failed (${r.status})`);
  return data;
}

function formatSize(n) {
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i];
}

function formatTime(ms) {
  const d = new Date(ms);
  const today = new Date();
  return d.toDateString() === today.toDateString()
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString([], { day: 'numeric', month: 'short' });
}

function guessDeviceName() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua)) return 'iPad';
  if (/Android/.test(ua)) return /Mobile/.test(ua) ? 'Android phone' : 'Android tablet';
  if (/Windows/.test(ua)) return 'Windows laptop';
  if (/Mac/.test(ua)) return 'Mac';
  return 'My device';
}

const fileUrl = (name, download) => `/api/files/${encodeURIComponent(name)}${download ? '?dl=1' : ''}`;

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------
let me = null;

async function showPair() {
  $('mainView').classList.add('hidden');
  $('pairView').classList.remove('hidden');
  $('who').textContent = '';
  $('deviceName').value ||= guessDeviceName();
  if (me && me.local) {
    // Opened on the laptop itself: fetch the code automatically.
    try {
      const { code } = await api('GET', '/api/local-code');
      $('pairCode').value = code.slice(0, 4) + '-' + code.slice(4);
      $('pairHint').textContent = 'This is the laptop running Dabba. Press "Pair device" to continue.';
    } catch (_) { /* ignore */ }
  }
}

$('pairForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('pairError').textContent = '';
  const btn = e.submitter || $('pairForm').querySelector('button');
  btn.disabled = true;
  try {
    await api('POST', '/api/pair', { code: $('pairCode').value, name: $('deviceName').value });
    $('pairCode').value = '';
    await boot();
  } catch (err) {
    $('pairError').textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// File list
// ---------------------------------------------------------------------------
async function loadFiles() {
  const { files } = await api('GET', '/api/files');
  const grid = $('files');
  grid.replaceChildren();
  $('fileCount').textContent = files.length ? `(${files.length})` : '';
  $('empty').classList.toggle('hidden', files.length > 0);

  for (const f of files) {
    const isImg = f.previewable && f.type.startsWith('image/');
    const isVid = f.previewable && f.type.startsWith('video/');
    let media;
    if (isImg) media = el('img', { src: fileUrl(f.name), loading: 'lazy', alt: '', decoding: 'async' });
    else if (isVid) media = el('video', { src: fileUrl(f.name) + '#t=0.1', preload: 'metadata', muted: '', playsinline: '' });
    else media = el('span', { class: 'ext', text: (f.name.split('.').pop() || 'file').slice(0, 5) });

    const thumb = el('button', { class: 'thumb', type: 'button', title: f.name, onclick: () => openPreview(f) },
      [media, isVid ? el('span', { class: 'badge', text: '▶ video' }) : null]);

    const del = el('button', {
      class: 'danger', type: 'button', text: 'Delete',
      onclick: async () => {
        if (!confirm(`Delete "${f.name}" from the shared folder?`)) return;
        try { await api('DELETE', fileUrl(f.name)); loadFiles(); } catch (err) { alert(err.message); }
      },
    });

    grid.append(el('div', { class: 'tile' }, [
      thumb,
      el('div', { class: 'meta' }, [
        el('div', { class: 'name ellipsis', text: f.name, title: f.name }),
        el('div', { class: 'sub ellipsis', text: `${formatSize(f.size)} · ${f.from} · ${formatTime(f.modified)}` }),
      ]),
      el('div', { class: 'tile-actions' }, [
        el('a', { class: 'button ghost', href: fileUrl(f.name, true), download: f.name, text: 'Save' }),
        del,
      ]),
    ]));
  }
}

function openPreview(f) {
  const body = $('previewBody');
  body.replaceChildren();
  $('previewName').textContent = f.name;
  $('previewDownload').href = fileUrl(f.name, true);
  $('previewDownload').setAttribute('download', f.name);
  if (f.previewable && f.type.startsWith('image/')) body.append(el('img', { src: fileUrl(f.name), alt: f.name }));
  else if (f.previewable && f.type.startsWith('video/')) body.append(el('video', { src: fileUrl(f.name), controls: '', autoplay: '', playsinline: '' }));
  else if (f.previewable && f.type.startsWith('audio/')) body.append(el('audio', { src: fileUrl(f.name), controls: '' }));
  else if (f.previewable && f.type === 'application/pdf') {
    // Phone browsers (Android Chrome especially) can't show PDFs inside a page, so open them in their own tab there.
    if (window.matchMedia('(hover: none) and (pointer: coarse)').matches) {
      body.append(el('div', { class: 'pdf-mobile' }, [
        el('p', { class: 'muted', text: 'PDFs open in your phone\'s PDF viewer.' }),
        el('a', { class: 'button primary', href: fileUrl(f.name), target: '_blank', rel: 'noopener', text: 'Open PDF' }),
      ]));
    } else {
      body.append(el('iframe', { class: 'pdf-frame', src: fileUrl(f.name), title: f.name }));
    }
  }
  else body.append(el('p', { class: 'muted', text: 'No preview for this file type. Use Download.' }));
  $('previewDialog').showModal();
}

$('previewDialog').addEventListener('close', () => $('previewBody').replaceChildren()); // stops video playback

// ---------------------------------------------------------------------------
// Uploads (XHR so we get progress events; 2 at a time)
// ---------------------------------------------------------------------------
const queue = [];
let active = 0;

function enqueue(fileList) {
  for (const file of fileList) {
    const bar = el('span');
    const status = el('span', { class: 'muted', text: 'Waiting…' });
    const row = el('div', { class: 'upload' }, [
      el('div', { class: 'row' }, [el('span', { class: 'ellipsis', text: file.name }), status]),
      el('div', { class: 'bar' }, [bar]),
    ]);
    $('uploads').prepend(row);
    queue.push({ file, row, bar, status });
  }
  pump();
}

function pump() {
  while (active < 2 && queue.length) {
    active++;
    upload(queue.shift()).finally(() => { active--; pump(); });
  }
}

function upload({ file, row, bar, status }) {
  return new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', '/api/upload');
    xhr.setRequestHeader('X-Dabba', '1');
    xhr.setRequestHeader('X-File-Name', encodeURIComponent(file.name));
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.upload.onprogress = (e) => {
      if (!e.lengthComputable) return;
      const pct = Math.round((e.loaded / e.total) * 100);
      bar.style.width = pct + '%';
      status.textContent = `${pct}% of ${formatSize(e.total)}`;
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        row.classList.add('done');
        bar.style.width = '100%';
        status.textContent = 'Sent ✓';
        setTimeout(() => row.remove(), 4000);
      } else {
        let msg = `Failed (${xhr.status})`;
        try { msg = JSON.parse(xhr.responseText).error || msg; } catch (_) { /* ignore */ }
        row.classList.add('failed');
        status.textContent = msg;
      }
      resolve();
    };
    xhr.onerror = () => { row.classList.add('failed'); status.textContent = 'Connection lost'; resolve(); };
    xhr.send(file);
  });
}

$('fileInput').addEventListener('change', (e) => { enqueue(e.target.files); e.target.value = ''; });

const dz = $('dropzone');
['dragenter', 'dragover'].forEach((t) => document.addEventListener(t, (e) => { e.preventDefault(); dz.classList.add('over'); }));
['dragleave', 'drop'].forEach((t) => document.addEventListener(t, (e) => { e.preventDefault(); if (t === 'drop' || !e.relatedTarget) dz.classList.remove('over'); }));
document.addEventListener('drop', (e) => { if (e.dataTransfer && e.dataTransfer.files.length) enqueue(e.dataTransfer.files); });

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------
async function loadDevices() {
  const { devices } = await api('GET', '/api/devices');
  const list = $('deviceList');
  list.replaceChildren();
  for (const d of devices) {
    list.append(el('li', {}, [
      el('div', {}, [
        el('div', {}, [document.createTextNode(d.name), d.isYou ? el('span', { class: 'you', text: '(this device)' }) : null]),
        el('div', { class: 'muted small', text: `Paired ${new Date(d.createdAt).toLocaleDateString()} · last seen ${formatTime(d.lastSeen)}` }),
      ]),
      el('button', {
        class: 'danger', type: 'button', text: d.isYou ? 'Unpair' : 'Revoke',
        onclick: async () => {
          if (!confirm(`Remove access for "${d.name}"?`)) return;
          await api('DELETE', `/api/devices/${d.id}`);
          if (d.isYou) location.reload(); else loadDevices();
        },
      }),
    ]));
  }
}

$('devicesBtn').addEventListener('click', async () => {
  $('newCodeBox').classList.add('hidden');
  await loadDevices();
  $('devicesDialog').showModal();
});

$('addDeviceBtn').addEventListener('click', async () => {
  const { code, urls } = await api('POST', '/api/pair/new');
  $('newCode').textContent = code.slice(0, 4) + '-' + code.slice(4);
  $('newCodeUrls').replaceChildren(...urls.map((u) => el('div', { text: u })));
  $('newCodeBox').classList.remove('hidden');
});

$('openFolderBtn').addEventListener('click', () => api('POST', '/api/open-folder').catch((e) => alert(e.message)));

document.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => b.closest('dialog').close()));

// ---------------------------------------------------------------------------
// Live updates
// ---------------------------------------------------------------------------
let events = null;
function listen() {
  if (events) events.close();
  events = new EventSource('/api/events');
  events.addEventListener('files', () => loadFiles().catch(() => {}));
  events.addEventListener('devices', () => { if ($('devicesDialog').open) loadDevices().catch(() => {}); });
  events.onerror = () => { /* browser retries automatically; check we are still paired */
    fetch('/api/me').then((r) => r.json()).then((m) => { if (!m.paired) { events.close(); showPair(); } }).catch(() => {});
  };
}

// Refresh when returning to the app (phones suspend background tabs)
document.addEventListener('visibilitychange', () => { if (!document.hidden && me && me.paired) loadFiles().catch(() => {}); });

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
async function boot() {
  me = await (await fetch('/api/me')).json();
  if (!me.paired) return showPair();
  $('pairView').classList.add('hidden');
  $('mainView').classList.remove('hidden');
  $('who').textContent = me.name;
  $('openFolderBtn').classList.toggle('hidden', !me.local);
  await loadFiles();
  listen();
}

boot().catch((e) => console.error(e));
