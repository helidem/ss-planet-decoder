# ss -planet decoder

Paste the output of `ss -planet` (ideally `sudo ss -planet`) and get a readable breakdown:

- **Where each port is bound** — localhost only (`127.0.0.0/8`, `::1`), all interfaces (`0.0.0.0`, `[::]`, `*`), or one specific private/public address
- **Which program owns it** — process name, PID and file descriptor when run as root, otherwise inferred from the systemd unit in the cgroup path
- **Who it runs as** — UID, with optional name lookup by pasting `getent passwd`
- **Connections** — inbound vs outbound, remote address, state, keepalive/retransmit timers
- **Notes** — e.g. clear-text or database ports open to the network
- Filter box and JSON export

Everything runs in the browser. No data leaves the page (the bundled CSP sets `connect-src 'none'`).

## Run locally

```bash
npx serve .
```

## Test

```bash
npm test
```

## Deploy to Vercel

Static site, no build step. Import the repository in Vercel and deploy with the defaults, or:

```bash
npx vercel --prod
```
