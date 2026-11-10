import { analyze, parsePasswd, EXAMPLE, SCOPES } from './parser.js';

const $ = (id) => document.getElementById(id);
const input = $('input');
const passwd = $('passwd');
const filter = $('filter');
let current = null;

// Tiny DOM builder: everything goes through textContent, so pasted text is never parsed as HTML.
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const chip = (text, kind) => h('span', { class: `chip ${kind || ''}` }, text);

function addr(ep) {
  const ip = ep.ip.includes(':') ? `[${ep.ip}]` : ep.ip;
  return `${ip}${ep.iface ? `%${ep.iface}` : ''}:${ep.portRaw}`;
}

function processText(s) {
  if (!s.processes.length) return 'Not shown (ss was run without root)';
  return s.processes.map((p) => `${p.name} — PID ${p.pid}, file descriptor ${p.fd}`).join('\n');
}

function detailRows(s) {
  const L = s.local;
  const rows = [
    ['State', `${s.stateLabel} (${s.state}) — ${s.stateDesc}`],
    ['Program', s.service.name + ({
      process: '', cgroup: ' — identified from its systemd unit', port: '', unknown: '',
    }[s.service.source])],
    ['Process', processText(s)],
    ['Runs as', s.userText + (s.uidShown ? '' : ' — ss omits the UID when it is 0')],
    ['Local address', `${addr(L)} — ${SCOPES[L.scope].desc}`],
    L.iface && ['Interface', L.iface === 'lo' ? 'lo (loopback)' : L.iface],
    s.kind === 'conn' && ['Remote address', `${addr(s.peer)} — ${SCOPES[s.peer.scope].short}`],
    s.kind === 'conn' && ['Direction', s.direction === 'inbound'
      ? 'Inbound — the remote side connected to a port this host listens on'
      : 'Outbound — this host opened the connection'],
    ['IP version', s.ipVersions + (s.v6only != null ? ` (v6only:${s.v6only})` : '')],
    ['Queues', `${s.queueText} (Recv-Q ${s.recvQ}, Send-Q ${s.sendQ})`],
    s.timerText && ['Timer', s.timerText],
    s.cgroup && ['Control group', s.cgroup],
    s.fwmark && ['Firewall mark', s.fwmark],
    ['Kernel ids', [s.ino != null && `inode ${s.ino}`, s.sk && `socket id ${s.sk}`].filter(Boolean).join(', ') || '—'],
  ].filter(Boolean);
  return h('dl', { class: 'kv' }, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
}

function card(s) {
  const L = s.local;
  const pids = s.processes.map((p) => p.pid);
  const title = s.kind === 'listen'
    ? s.service.name
    : `${s.peer.ip} ${s.direction === 'inbound' ? '→' : '←'} ${s.service.name}`;
  const el = h('details', { class: `card scope-${L.scope}` },
    h('summary', null,
      h('span', { class: 'port' }, h('b', null, L.portRaw), h('small', null, s.proto.toUpperCase())),
      h('span', { class: 'body' },
        h('span', { class: 'title' }, title),
        h('span', { class: 'sentence' }, s.sentence),
        h('span', { class: 'chips' },
          s.kind === 'listen' && chip(SCOPES[L.scope].label, `scope ${L.scope}`),
          chip(addr(L), 'mono'),
          s.kind === 'listen' && chip(s.ipVersions),
          s.kind === 'conn' && chip(s.stateLabel),
          chip(s.userText),
          pids.length ? chip(`PID ${pids.join(', ')}`) : null,
          s.unit && chip(s.unit, 'mono'),
        ),
      ),
    ),
    h('div', { class: 'more' }, detailRows(s), h('pre', { class: 'raw' }, s.raw)),
  );
  el.dataset.hay = [s.raw, s.sentence, s.service.name, s.userText, SCOPES[L.scope].label, s.stateLabel, s.portName].join(' ').toLowerCase();
  return el;
}

function group(title, desc, sockets, scope) {
  if (!sockets.length) return null;
  sockets = [...sockets].sort((a, b) => (a.local.port ?? 1e9) - (b.local.port ?? 1e9));
  return h('section', { class: `group ${scope ? `scope-${scope}` : ''}` },
    h('h2', null, title, h('span', { class: 'count' }, sockets.length)),
    h('p', { class: 'desc' }, desc),
    sockets.map(card),
  );
}

function render() {
  const text = input.value;
  const has = text.trim().length > 0;
  current = has ? analyze(text, { users: parsePasswd(passwd.value) }) : null;
  $('results').hidden = !has;
  $('empty').hidden = has;
  if (!has) return;
  const { sockets, summary, findings, skipped } = current;

  $('tiles').replaceChildren(...[
    ['Sockets', summary.total, ''],
    ['Listening', summary.listening, ''],
    ['Localhost only', summary.localhostOnly, 'loopback'],
    ['Network-reachable', summary.exposed + summary.specific, 'all'],
    ['Connections', summary.connections, ''],
  ].map(([label, n, cls]) => h('div', { class: `tile ${cls}` }, h('b', null, n), h('span', null, label))));

  $('findings').replaceChildren(...findings.map((f) =>
    h('p', { class: `finding ${f.level}` }, h('strong', null, f.level === 'warn' ? 'Check: ' : 'Note: '), f.text)));

  const listen = (scope) => sockets.filter((s) => s.kind === 'listen' && s.local.scope === scope);
  $('groups').replaceChildren(...[
    group('Listening on localhost only', SCOPES.loopback.desc, listen('loopback'), 'loopback'),
    group('Listening on all interfaces', SCOPES.all.desc, listen('all'), 'all'),
    group('Listening on a specific private address', SCOPES.private.desc, listen('private'), 'private'),
    group('Listening on a specific public address', SCOPES.public.desc, listen('public'), 'public'),
    group('Connections', 'Sockets that are connected to (or connecting to) a remote address.', sockets.filter((s) => s.kind === 'conn')),
  ].filter(Boolean));
  if (!sockets.length) $('groups').append(h('p', { class: 'empty' }, 'No sockets found in this text.'));

  const sk = $('skipped');
  sk.hidden = !skipped.length;
  sk.replaceChildren(
    h('summary', null, `${skipped.length} line${skipped.length === 1 ? '' : 's'} could not be read`),
    h('pre', { class: 'raw' }, skipped.map((l) => `line ${l.line}: ${l.text}`).join('\n')),
  );
  applyFilter();
}

function applyFilter() {
  const terms = filter.value.toLowerCase().split(/\s+/).filter(Boolean);
  for (const g of document.querySelectorAll('.group')) {
    let shown = 0;
    for (const c of g.querySelectorAll('.card')) {
      const ok = terms.every((t) => c.dataset.hay.includes(t));
      c.hidden = !ok;
      if (ok) shown++;
    }
    g.hidden = shown === 0;
  }
}

let timer;
const debounced = () => { clearTimeout(timer); timer = setTimeout(render, 120); };
input.addEventListener('input', debounced);
passwd.addEventListener('input', debounced);
filter.addEventListener('input', applyFilter);
$('example').addEventListener('click', () => { input.value = EXAMPLE; render(); });
$('clear').addEventListener('click', () => { input.value = ''; filter.value = ''; render(); input.focus(); });
$('export').addEventListener('click', () => {
  if (!current) return;
  const blob = new Blob([JSON.stringify(current, null, 2)], { type: 'application/json' });
  const a = h('a', { href: URL.createObjectURL(blob), download: 'ss-planet.json' });
  a.click();
  URL.revokeObjectURL(a.href);
});
render();
