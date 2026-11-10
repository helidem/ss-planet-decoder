// Parser + analyser for `ss -planet` style output (iproute2).
// Pure functions, no DOM: used by the browser UI and by the Node tests.

export const EXAMPLE = `State    Recv-Q   Send-Q        Local Address:Port        Peer Address:Port   Process
LISTEN   0        4096          127.0.0.53%lo:53               0.0.0.0:*       uid:102 ino:21043 sk:1 cgroup:/system.slice/systemd-resolved.service <->
LISTEN   0        128                 0.0.0.0:22               0.0.0.0:*       ino:21996 sk:2 cgroup:/system.slice/ssh.service <->
ESTAB    0        0           192.168.115.144:22          10.13.115.50:50438   timer:(keepalive,101min,0) ino:40426 sk:6 cgroup:/system.slice/ssh.service <->
LISTEN   0        511                       *:80                     *:*       ino:22020 sk:3 cgroup:/system.slice/apache2.service v6only:0 <->
LISTEN   0        32                        *:21                     *:*       ino:21793 sk:4 cgroup:/system.slice/vsftpd.service v6only:0 <->
LISTEN   0        128                    [::]:22                  [::]:*       ino:22030 sk:5 cgroup:/system.slice/ssh.service v6only:1 <->
`;

const NETIDS = new Set([
  'tcp', 'udp', 'raw', 'mptcp', 'sctp', 'dccp', 'udplite', 'icmp6',
  'u_str', 'u_dgr', 'u_seq', 'nl', 'p_raw', 'p_dgr', 'tipc', 'v_str', 'v_dgr', 'xdp',
]);

export const STATES = {
  'LISTEN': { label: 'Listening', desc: 'Waiting for incoming connections.' },
  'ESTAB': { label: 'Established', desc: 'An open, active connection.' },
  'UNCONN': { label: 'Unconnected', desc: 'Bound but not connected (normal for UDP sockets waiting for datagrams).' },
  'SYN-SENT': { label: 'Connecting', desc: 'This host sent a SYN and is waiting for the peer to answer.' },
  'SYN-RECV': { label: 'Handshake in progress', desc: 'A SYN was received; the handshake is not finished yet.' },
  'FIN-WAIT-1': { label: 'Closing', desc: 'This host closed the connection and waits for the peer to acknowledge.' },
  'FIN-WAIT-2': { label: 'Half-closed', desc: 'This side is closed; waiting for the peer to close its side.' },
  'TIME-WAIT': { label: 'Time-wait', desc: 'Connection is closed; the kernel keeps it briefly to absorb late packets.' },
  'CLOSE-WAIT': { label: 'Peer closed', desc: 'The peer closed the connection; the local program has not closed its side yet.' },
  'LAST-ACK': { label: 'Closing', desc: 'Both sides closed; waiting for the final acknowledgement.' },
  'CLOSING': { label: 'Closing', desc: 'Both sides are closing at the same time.' },
  'CLOSED': { label: 'Closed', desc: 'The socket is not in use.' },
};

// systemd unit (without .service) or process name -> friendly name
const SERVICES = {
  'ssh': 'OpenSSH server', 'sshd': 'OpenSSH server',
  'apache2': 'Apache HTTP Server', 'httpd': 'Apache HTTP Server',
  'nginx': 'nginx web server', 'lighttpd': 'lighttpd web server', 'caddy': 'Caddy web server',
  'haproxy': 'HAProxy load balancer', 'squid': 'Squid proxy',
  'vsftpd': 'vsftpd FTP server', 'proftpd': 'ProFTPD FTP server',
  'systemd-resolved': 'systemd-resolved (local DNS resolver)', 'systemd-resolve': 'systemd-resolved (local DNS resolver)',
  'systemd-timesyncd': 'systemd time sync', 'systemd-networkd': 'systemd-networkd',
  'systemd': 'systemd', 'init': 'systemd (init)',
  'named': 'BIND DNS server', 'bind9': 'BIND DNS server', 'dnsmasq': 'dnsmasq (DNS/DHCP)', 'unbound': 'Unbound DNS resolver',
  'mysql': 'MySQL database', 'mysqld': 'MySQL database', 'mariadb': 'MariaDB database', 'mariadbd': 'MariaDB database',
  'postgresql': 'PostgreSQL database', 'postgres': 'PostgreSQL database',
  'redis': 'Redis', 'redis-server': 'Redis', 'memcached': 'Memcached',
  'mongod': 'MongoDB', 'mongodb': 'MongoDB', 'elasticsearch': 'Elasticsearch',
  'docker': 'Docker daemon', 'dockerd': 'Docker daemon', 'docker-proxy': 'Docker port forward', 'containerd': 'containerd',
  'kubelet': 'Kubernetes kubelet', 'k3s': 'K3s (Kubernetes)', 'libvirtd': 'libvirt daemon',
  'cups': 'CUPS printing service', 'cupsd': 'CUPS printing service', 'cups-browsed': 'CUPS printer discovery',
  'avahi-daemon': 'Avahi (mDNS/Bonjour)', 'chronyd': 'chrony time sync', 'chrony': 'chrony time sync', 'ntpd': 'NTP daemon',
  'NetworkManager': 'NetworkManager', 'rpcbind': 'rpcbind (RPC port mapper)',
  'postfix': 'Postfix mail server', 'master': 'Postfix mail server', 'exim4': 'Exim mail server', 'dovecot': 'Dovecot mail server',
  'smbd': 'Samba file sharing', 'nmbd': 'Samba NetBIOS', 'xrdp': 'xrdp remote desktop',
  'grafana-server': 'Grafana', 'prometheus': 'Prometheus', 'node_exporter': 'Prometheus node exporter',
  'jenkins': 'Jenkins', 'tomcat': 'Apache Tomcat', 'rabbitmq-server': 'RabbitMQ', 'kafka': 'Apache Kafka', 'zookeeper': 'ZooKeeper',
  'openvpn': 'OpenVPN', 'tailscaled': 'Tailscale', 'tor': 'Tor', 'snapd': 'snapd', 'cockpit': 'Cockpit web console',
  'node': 'Node.js', 'python3': 'Python', 'python': 'Python', 'java': 'Java application',
};

export const PORTS = {
  20: 'FTP data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP server', 68: 'DHCP client',
  69: 'TFTP', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3', 111: 'rpcbind', 123: 'NTP', 135: 'MS RPC', 137: 'NetBIOS',
  138: 'NetBIOS', 139: 'NetBIOS/SMB', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
  514: 'syslog', 546: 'DHCPv6 client', 587: 'SMTP submission', 631: 'IPP printing', 636: 'LDAPS', 873: 'rsync',
  993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS proxy', 1194: 'OpenVPN', 1433: 'MS SQL Server', 1521: 'Oracle DB',
  1883: 'MQTT', 2049: 'NFS', 2181: 'ZooKeeper', 2375: 'Docker API (no TLS)', 2376: 'Docker API (TLS)',
  2379: 'etcd', 2380: 'etcd peer', 3000: 'dev server / Grafana', 3306: 'MySQL/MariaDB', 3389: 'RDP',
  5000: 'dev server', 5353: 'mDNS', 5355: 'LLMNR', 5432: 'PostgreSQL', 5672: 'AMQP', 5900: 'VNC', 5984: 'CouchDB',
  6379: 'Redis', 6443: 'Kubernetes API', 8000: 'HTTP (alt)', 8080: 'HTTP (alt)', 8443: 'HTTPS (alt)',
  8888: 'HTTP (alt)', 9000: 'HTTP (alt)', 9090: 'Prometheus', 9092: 'Kafka', 9100: 'node exporter',
  9200: 'Elasticsearch', 10250: 'kubelet', 11211: 'Memcached', 27017: 'MongoDB', 51820: 'WireGuard',
};

// Listening on a network-reachable address with one of these deserves a note.
const RISKY = {
  21: 'FTP sends credentials and files in clear text',
  23: 'Telnet sends everything, including passwords, in clear text',
  111: 'rpcbind is rarely needed outside NFS setups',
  445: 'SMB file sharing should not be reachable from untrusted networks',
  2049: 'NFS should not be reachable from untrusted networks',
  2375: 'the unencrypted Docker API gives root-equivalent access to this host',
  3306: 'databases are usually best bound to localhost or a private address',
  3389: 'remote desktop is a common brute-force target',
  5432: 'databases are usually best bound to localhost or a private address',
  5900: 'VNC is a common brute-force target and is often unencrypted',
  6379: 'Redis often runs without authentication',
  9200: 'Elasticsearch often runs without authentication',
  11211: 'Memcached has no authentication',
  27017: 'databases are usually best bound to localhost or a private address',
};

export const SCOPES = {
  loopback: { label: 'Localhost only', short: 'localhost', desc: 'Bound to 127.0.0.0/8 or ::1 — reachable only from this machine.' },
  all: { label: 'All interfaces', short: 'all interfaces', desc: 'Bound to 0.0.0.0, [::] or * — reachable from every network this host is on, unless a firewall blocks it.' },
  private: { label: 'Specific private address', short: 'private address', desc: 'Bound to one private / link-local address — reachable only through that network.' },
  public: { label: 'Specific public address', short: 'public address', desc: 'Bound to one publicly routable address.' },
};

function parseEndpoint(addr, port) {
  const iface = (addr.match(/%([^\]]+)/) || [])[1] || null;
  const ip = addr.replace(/%[^\]]+/, '').replace(/^\[|\]$/g, '');
  const portNum = /^\d+$/.test(port) ? Number(port) : null;
  return { raw: `${addr}:${port}`, ip, iface, port: portNum, portRaw: port, ...classify(ip, iface) };
}

function splitAddrPort(tok) {
  const i = tok.lastIndexOf(':');
  return i < 0 ? [tok, ''] : [tok.slice(0, i), tok.slice(i + 1)];
}

function classify(ip, iface) {
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  const v4 = mapped ? mapped[1] : (/^\d+\.\d+\.\d+\.\d+$/.test(ip) ? ip : null);
  let family = ip === '*' ? 'any' : v4 && !mapped ? 'IPv4' : mapped ? 'IPv4-mapped IPv6' : ip.includes(':') ? 'IPv6' : 'other';
  let scope;
  if (ip === '*' || ip === '0.0.0.0' || ip === '::') scope = 'all';
  else if (iface === 'lo' || ip === '::1' || (v4 && v4.startsWith('127.'))) scope = 'loopback';
  else if (v4) {
    const [a, b] = v4.split('.').map(Number);
    scope = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) ? 'private' : 'public';
  } else if (/^(fe[89ab]|f[cd])/i.test(ip)) scope = 'private';
  else scope = family === 'other' ? 'private' : 'public';
  return { family, scope };
}

function parseDetails(rest) {
  const d = { processes: [], uid: 0, uidShown: false, ino: null, sk: null, cgroup: null, v6only: null, timer: null, fwmark: null, shutdown: null };
  const users = rest.match(/users:\(\((.*)\)\)/);
  if (users) {
    const re = /"((?:[^"\\]|\\.)*)",pid=(\d+),fd=(\d+)/g;
    let m;
    while ((m = re.exec(users[1]))) d.processes.push({ name: m[1], pid: Number(m[2]), fd: Number(m[3]) });
    rest = rest.replace(users[0], ' ');
  }
  let m;
  if ((m = rest.match(/timer:\(([^,)]+),([^,)]*),(\d+)\)/))) d.timer = { name: m[1], expires: m[2], retrans: Number(m[3]) };
  if ((m = rest.match(/(?:^|\s)uid:(\d+)/))) { d.uid = Number(m[1]); d.uidShown = true; }
  if ((m = rest.match(/(?:^|\s)ino:(\d+)/))) d.ino = Number(m[1]);
  if ((m = rest.match(/(?:^|\s)sk:([0-9a-f]+)/i))) d.sk = m[1];
  if ((m = rest.match(/(?:^|\s)cgroup:(\S+)/))) d.cgroup = m[1];
  if ((m = rest.match(/(?:^|\s)v6only:(\d)/))) d.v6only = Number(m[1]);
  if ((m = rest.match(/(?:^|\s)fwmark:(\S+)/))) d.fwmark = m[1];
  if ((m = rest.match(/(?:^|\s)(<->|-->|<--|---)(?:\s|$)/))) d.shutdown = m[1];
  return d;
}

function friendly(name) {
  return SERVICES[name] || SERVICES[name.replace(/@.*$/, '')] || null;
}

// Turn a cgroup path into something a human can read.
export function describeCgroup(cgroup) {
  if (!cgroup || cgroup === '/') return null;
  const leaf = cgroup.split('/').filter(Boolean).pop();
  let m;
  if ((m = cgroup.match(/docker[-/]([0-9a-f]{12})[0-9a-f]*/))) return { unit: leaf, name: `Docker container ${m[1]}` };
  if ((m = leaf.match(/^session-(\d+)\.scope$/))) return { unit: leaf, name: `a program started from login session ${m[1]}` };
  if ((m = leaf.match(/^user@(\d+)\.service$/))) return { unit: leaf, name: `user services of UID ${m[1]}` };
  if ((m = leaf.match(/^(.+)\.(service|socket)$/))) return { unit: leaf, name: friendly(m[1]) || m[1] };
  if ((m = leaf.match(/^(?:app|run)-(.+?)(?:-[0-9a-f]+)?\.scope$/))) return { unit: leaf, name: m[1] };
  return { unit: leaf, name: leaf };
}

export function parsePasswd(text) {
  const map = {};
  for (const line of (text || '').split('\n')) {
    const f = line.trim().split(':');
    if (f.length >= 3 && /^\d+$/.test(f[2]) && f[0]) map[Number(f[2])] = f[0];
  }
  return map;
}

function humanTimer(t) {
  if (!t) return null;
  const names = {
    keepalive: 'Keepalive probe', on: 'Retransmission', timewait: 'TIME-WAIT cleanup',
    persist: 'Zero-window probe', off: 'No timer',
  };
  const when = t.expires.replace(/(\d)(min|sec|ms)/g, '$1 $2');
  return `${names[t.name] || `Timer "${t.name}"`} due in ${when}` + (t.retrans ? `, ${t.retrans} retransmission${t.retrans > 1 ? 's' : ''} so far` : '');
}

function hostText(ep) {
  const ip = ep.ip.includes(':') ? `[${ep.ip}]` : ep.ip;
  return ep.iface ? `${ip} on ${ep.iface}` : ip;
}

export function analyze(text, opts = {}) {
  const users = { 0: 'root', ...(opts.users || {}) };
  const sockets = [];
  const skipped = [];
  let sawHeader = false;

  (text || '').replace(/\r/g, '').split('\n').forEach((rawLine, idx) => {
    const line = rawLine.trim();
    if (!line) return;
    if (/^(Netid\s+)?State\s+Recv-Q/i.test(line)) { sawHeader = true; return; }
    const tok = line.split(/\s+/);
    let i = 0;
    let netid = null;
    if (NETIDS.has(tok[0].toLowerCase()) && tok.length > 1) netid = tok[i++].toLowerCase();
    const state = (tok[i] || '').toUpperCase();
    if (!STATES[state] || !/^\d+$/.test(tok[i + 1] || '') || !/^\d+$/.test(tok[i + 2] || '')) {
      // Not a socket line: wrapped detail line of the previous socket, or junk.
      if (sockets.length && /(\w+:\S|<->)/.test(line)) sockets[sockets.length - 1]._rest += ' ' + line;
      else skipped.push({ line: idx + 1, text: line });
      return;
    }
    const recvQ = Number(tok[i + 1]);
    const sendQ = Number(tok[i + 2]);
    i += 3;
    let local, peer;
    const unixLike = netid && /^(u_|nl|p_|v_|tipc|xdp)/.test(netid);
    if (unixLike || (tok[i] && !tok[i].includes(':') && tok.length >= i + 4)) {
      local = parseEndpoint(tok[i], tok[i + 1] || '');
      peer = parseEndpoint(tok[i + 2] || '*', tok[i + 3] || '');
      i += 4;
    } else {
      if (tok.length < i + 2) { skipped.push({ line: idx + 1, text: line }); return; }
      local = parseEndpoint(...splitAddrPort(tok[i]));
      peer = parseEndpoint(...splitAddrPort(tok[i + 1]));
      i += 2;
    }
    const rest = line.replace(new RegExp(`^(?:\\S+\\s+){${i - 1}}\\S+\\s*`), '');
    sockets.push({ line: idx + 1, raw: line, netid, proto: netid || 'tcp', state, recvQ, sendQ, local, peer, _rest: rest });
  });

  const listenPorts = new Set();
  for (const s of sockets) {
    Object.assign(s, parseDetails(s._rest));
    delete s._rest;
    s.kind = s.state === 'LISTEN' || (s.state === 'UNCONN' && s.peer.portRaw === '*') ? 'listen' : 'conn';
    if (s.kind === 'listen' && s.local.port != null) listenPorts.add(`${s.proto}:${s.local.port}`);
  }

  for (const s of sockets) {
    s.user = users[s.uid] || null;
    s.userText = s.user ? `${s.user} (UID ${s.uid})` : `UID ${s.uid}`;
    s.stateLabel = STATES[s.state].label;
    s.stateDesc = STATES[s.state].desc;
    s.portName = PORTS[s.local.port] || null;
    s.timerText = humanTimer(s.timer);
    const cg = describeCgroup(s.cgroup);
    s.unit = cg ? cg.unit : null;

    // Who owns this socket, best evidence first.
    const names = [...new Set(s.processes.map((p) => p.name))];
    if (names.length) s.service = { name: names.map((n) => friendly(n) ? `${friendly(n)} (${n})` : n).join(', '), source: 'process' };
    else if (cg) s.service = { name: cg.name, source: 'cgroup' };
    else if (s.portName && s.kind === 'listen') s.service = { name: `Unknown program (port suggests ${s.portName})`, source: 'port' };
    else s.service = { name: 'Unknown program', source: 'unknown' };

    const L = s.local;
    if (s.kind === 'listen') {
      s.ipVersions = L.ip === '*' ? (s.v6only === 1 ? 'IPv6' : 'IPv4 + IPv6')
        : L.ip === '::' ? (s.v6only === 0 ? 'IPv4 + IPv6' : 'IPv6')
        : L.family === 'IPv4' ? 'IPv4' : L.family;
      s.queueText = s.state === 'LISTEN'
        ? `${s.recvQ} connection${s.recvQ === 1 ? '' : 's'} waiting to be accepted, backlog limit ${s.sendQ}`
        : `${s.recvQ} bytes received and not yet read`;
      const where = {
        loopback: `only on localhost (${hostText(L)}) — other machines cannot reach it`,
        all: `on all interfaces (${s.ipVersions}) — reachable from the network unless a firewall blocks it`,
        private: `only on ${hostText(L)}, a private address`,
        public: `on ${hostText(L)}, a public address`,
      }[L.scope];
      const port = L.port != null ? `port ${L.port}` : `port ${L.portRaw}`;
      s.sentence = `${s.service.name} ${s.state === 'LISTEN' ? 'is listening' : 'is bound'} on ${s.proto.toUpperCase()} ${port}${s.portName ? ` (${s.portName})` : ''} ${where}.`;
    } else {
      s.ipVersions = L.family;
      s.direction = listenPorts.has(`${s.proto}:${L.port}`) ? 'inbound' : 'outbound';
      s.queueText = `${s.recvQ} bytes received but not yet read by the program, ${s.sendQ} bytes sent but not yet acknowledged`;
      const peerPort = PORTS[s.peer.port];
      s.sentence = s.direction === 'inbound'
        ? `${s.peer.ip} (from its port ${s.peer.portRaw}) is connected to ${s.service.name} on local port ${L.portRaw}${s.portName ? ` (${s.portName})` : ''}.`
        : `${s.service.name} on this host (${L.ip}, port ${L.portRaw}) has a connection to ${s.peer.ip} port ${s.peer.portRaw}${peerPort ? ` (${peerPort})` : ''}.`;
      if (s.state !== 'ESTAB') s.sentence += ` State: ${s.stateLabel.toLowerCase()}.`;
    }
  }

  const listeners = sockets.filter((s) => s.kind === 'listen');
  const summary = {
    total: sockets.length,
    listening: listeners.length,
    connections: sockets.length - listeners.length,
    localhostOnly: listeners.filter((s) => s.local.scope === 'loopback').length,
    exposed: listeners.filter((s) => s.local.scope === 'all' || s.local.scope === 'public').length,
    specific: listeners.filter((s) => s.local.scope === 'private').length,
  };

  const findings = [];
  if (sockets.length && !sockets.some((s) => s.processes.length)) {
    findings.push({
      level: 'info',
      text: 'No process names or PIDs in this output — ss only shows them when run as root. Run "sudo ss -planet" to get them. Until then, programs are identified from their systemd unit (cgroup).',
    });
  }
  const seen = new Set();
  for (const s of listeners) {
    const why = RISKY[s.local.port];
    if (!why || seen.has(s.local.port) || (s.local.scope !== 'all' && s.local.scope !== 'public')) continue;
    seen.add(s.local.port);
    findings.push({ level: 'warn', text: `Port ${s.local.port} (${s.portName}) is open on ${SCOPES[s.local.scope].short}: ${why}.` });
  }
  if (!sawHeader && sockets.length === 0 && (text || '').trim()) {
    findings.push({ level: 'warn', text: 'Nothing here looks like ss output. Paste the full output of "ss -planet", including the header line.' });
  }

  return { sockets, skipped, summary, findings };
}
