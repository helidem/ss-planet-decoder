import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze, EXAMPLE, parsePasswd } from '../src/parser.js';

test('parses the example output', () => {
  const { sockets, summary, skipped, findings } = analyze(EXAMPLE);
  assert.equal(sockets.length, 6);
  assert.equal(skipped.length, 0);
  assert.deepEqual(summary, { total: 6, listening: 5, connections: 1, localhostOnly: 1, exposed: 4, specific: 0 });

  const dns = sockets[0];
  assert.equal(dns.local.ip, '127.0.0.53');
  assert.equal(dns.local.iface, 'lo');
  assert.equal(dns.local.port, 53);
  assert.equal(dns.local.scope, 'loopback');
  assert.equal(dns.uid, 102);
  assert.equal(dns.unit, 'systemd-resolved.service');
  assert.equal(dns.sk, '1');

  const ssh = sockets[1];
  assert.equal(ssh.local.scope, 'all');
  assert.equal(ssh.ipVersions, 'IPv4');
  assert.equal(ssh.userText, 'root (UID 0)');
  assert.equal(ssh.service.name, 'OpenSSH server');

  const conn = sockets[2];
  assert.equal(conn.kind, 'conn');
  assert.equal(conn.direction, 'inbound');
  assert.deepEqual(conn.timer, { name: 'keepalive', expires: '101min', retrans: 0 });
  assert.equal(conn.peer.port, 50438);

  assert.equal(sockets[3].ipVersions, 'IPv4 + IPv6');
  assert.equal(sockets[5].local.ip, '::');
  assert.equal(sockets[5].ipVersions, 'IPv6');

  assert.ok(findings.some((f) => f.level === 'info'));
  assert.ok(findings.some((f) => f.level === 'warn' && f.text.includes('Port 21')));
});

test('handles root output with users:, Netid column and odd process names', () => {
  const out = `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    127.0.0.1:5432      0.0.0.0:*     users:(("postgres",pid=911,fd=5)) uid:113 ino:3 sk:a cgroup:/system.slice/postgresql.service <->
tcp   LISTEN 0      511    [::1]:3000          [::]:*        users:(("Web Content",pid=42,fd=7),("node",pid=43,fd=9)) uid:1000 ino:4 sk:b cgroup:/user.slice/user-1000.slice/session-3.scope v6only:1 <->
udp   UNCONN 0      0      0.0.0.0:68          0.0.0.0:*     users:(("dhclient",pid=5,fd=6)) ino:5 sk:c <->
tcp   ESTAB  0      0      192.168.1.5:44321   93.184.216.34:443 users:(("curl",pid=77,fd=3)) uid:1000 ino:6 sk:d <->
garbage line`;
  const { sockets, summary, skipped } = analyze(out, { users: parsePasswd('alice:x:1000:1000::/home/alice:/bin/bash') });
  assert.equal(sockets.length, 4);
  assert.equal(skipped.length, 1);
  assert.equal(summary.localhostOnly, 2);
  assert.deepEqual(sockets[0].processes, [{ name: 'postgres', pid: 911, fd: 5 }]);
  assert.equal(sockets[1].processes[0].name, 'Web Content');
  assert.equal(sockets[1].processes.length, 2);
  assert.equal(sockets[1].local.scope, 'loopback');
  assert.equal(sockets[1].userText, 'alice (UID 1000)');
  assert.equal(sockets[2].proto, 'udp');
  assert.equal(sockets[2].kind, 'listen');
  assert.equal(sockets[3].direction, 'outbound');
  assert.equal(sockets[3].peer.scope, 'public');
  assert.match(sockets[3].sentence, /HTTPS/);
});

test('empty and junk input do not throw', () => {
  assert.equal(analyze('').sockets.length, 0);
  const r = analyze('hello world\nfoo');
  assert.equal(r.sockets.length, 0);
  assert.ok(r.findings.length);
});
