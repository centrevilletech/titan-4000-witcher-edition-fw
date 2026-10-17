# Current UI screenshots

These images are generated from the device build, with synthetic telemetry,
settings, documentation-range addresses and invented key fingerprints. The
capture browser is restricted to its local fixture server. No live unit or
customer account is used. They illustrate the interface, not measured results.

```bash
npm ci --prefix web
npm run build:rust-device --prefix web
node docs/screenshots/capture.mjs
```

Install Playwright Chromium once if needed: `cd web && npx playwright install chromium`.
The capture script checks browser errors and exercises the current alignment
controls rather than drawing static mockups. Regenerate after relevant UI changes.

| View | Image |
| --- | --- |
| Login and MAC/version | [Login](login.jpg) |
| Dashboard | [Light](overview.png), [dark](overview-dark.png) |
| Alignment | [Desktop](align.png) |
| IPv6 settings | [Desktop](ipv6.png) |
| SSH key management | [Desktop](ssh-keys.png) |
| Phone | [Dashboard](phone-overview.png), [alignment](phone-align.png), [network](phone-network.png) |
