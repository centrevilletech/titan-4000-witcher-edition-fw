// Regenerate the README screenshots from the UI bundle that ships in the image.
//
// The panel talks to a stub of its JSON API, so every value in a screenshot is
// demo data. No unit is contacted and nothing here ends up in the firmware.
//
//   npm ci --prefix web
//   npm run build:rust-device --prefix web
//   node docs/screenshots/capture.mjs
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {extname, resolve, sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {chromium} from '../../web/node_modules/@playwright/test/index.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const bundle = resolve(here, '../../web/dist-device');
const types = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.jpg': 'image/jpeg', '.woff': 'font/woff', '.woff2': 'font/woff2'};

// The unit serves the bundle under /ui/, and the bundle's asset URLs say so.
const server = createServer(async (request, response) => {
  const path = decodeURIComponent(new URL(request.url, 'http://unit').pathname);
  const file = resolve(bundle, '.' + (path === '/ui/' ? '/index.html' : path.replace(/^\/ui/, '')));
  if (!path.startsWith('/ui/') || !file.startsWith(bundle + sep)) { response.writeHead(404).end(); return; }
  try {
    const body = await readFile(file);
    response.writeHead(200, {'Content-Type': types[extname(file)] || 'application/octet-stream'}).end(body);
  } catch { response.writeHead(404).end(); }
});
await new Promise(done => server.listen(0, '127.0.0.1', done));
const origin = `http://127.0.0.1:${server.address().port}`;

// A demo unit. Addresses come from the documentation ranges.
const unit = {
  serial: 'GLOBAL00004000', model: 'Titan 4000', firmware: 'V1.6.0.P0.4172', mac: '02:00:5E:40:00:01',
  mode: 'IP Passthrough', name: 'Ridgeview East', mgmt: '10.64.0.42', customer: '198.51.100.24',
  customerV6: '2001:db8:4000::1', band: '48', earfcn: '55990', pci: 190, attached: true, plmn: '00101',
  ethernet: 1000, ipType: 'IPv4v6', registration: 'Registered', grant: 'Authorized', cbsdId: '', grantId: '', sasError: 'OK',
};
// 0 is an antenna pointed at nothing, 100 is one pointed at the tower.
const signal = (aim, n) => {
  const round = value => Math.round(value * 10) / 10;
  const rsrp = round(-112 + aim * 0.36 + Math.sin(n * 0.7) * 0.5);
  return {
    rsrp, chains: [rsrp, round(rsrp - 1.3 + Math.sin(n * 0.4) * 0.3)],
    sinr: round(1 + aim * 0.26 + Math.sin(n * 0.5) * 0.45),
    rsrq: round(-15.5 + aim * 0.085 + Math.sin(n * 0.3) * 0.25),
  };
};

const readonly = (id, label, group) => ({id, label, group, type: 'readonly'});
const choice = (id, label, group, options) => ({id, label, group, type: 'select', options: options.map(([value, text]) => ({value, label: text}))});
// Same fields, groups and wording as the unit's own answers for these sections.
const settings = {
  mode: {
    groups: [{id: 'connection', title: 'Internet Connection'}, {id: 'ipv6', title: 'IPv6 prefix delegation'}, {id: 'identity', title: 'Device identity & MTU'}],
    fields: [
      choice('mode', 'Operating mode', 'connection', [['0', 'NAT router'], ['1', 'IP passthrough']]),
      choice('ip_type', 'IP family', 'connection', [['0', 'IPv4'], ['1', 'IPv6'], ['2', 'IPv4 / IPv6']]),
      {...choice('ipv6_pd', 'IPv6 prefix delegation', 'ipv6', [['unset', 'Not set'], ['0', 'Off'], ['1', 'On']]),
        help: 'Off sets the unit IP family to IPv4, so the customer bearer is IPv4-only; management stays on its IPv4 address. On is supported only for a SIM with a static IPv6 block in the core. That block is fixed to the SIM and does not change. Leave the pin empty to learn it on the first attach; it is then kept. Unset means this was never saved, and an upgrade does not change the IP family. Saving Off or On re-attaches LTE and restores the previous setting if this unit does not come back. A different block from the core stops delegation and is shown below; stale addresses are not served.'},
      {id: 'pinned_prefix', label: 'Pinned IPv6 block', group: 'ipv6', type: 'text',
        help: 'The static /56 for this SIM, or the link /64 inside it. The keeper checks every attach against this pin.'},
      readonly('pd_saved', 'Saved choice', 'ipv6'), readonly('pd_bearer', 'Bearer /64', 'ipv6'),
      readonly('pd_delegated', 'Delegated prefix', 'ipv6'), readonly('pd_router', 'Router MAC', 'ipv6'),
      readonly('pd_health', 'Router health', 'ipv6'), readonly('pd_last_action', 'Last keeper action', 'ipv6'),
      {id: 'nat_enabled', label: 'NAT enabled', group: 'connection', type: 'checkbox'},
      choice('nat_mode', 'NAT mode', 'connection', [['combine', 'Combined management / data'], ['separate', 'Separate management / data']]),
      {id: 'custom_mtu', label: 'Custom MTU', group: 'identity', type: 'checkbox'},
      {id: 'mtu', label: 'WAN MTU', group: 'identity', type: 'number', min: 576, max: 1500},
      {id: 'name', label: 'Router name', group: 'identity', type: 'text'},
      {id: 'hostname', label: 'WAN hostname', group: 'identity', type: 'text'},
    ],
    values: {
      mode: '1', ip_type: '2', ipv6_pd: '1', pinned_prefix: '2001:db8:4000::/56',
      pd_saved: 'On. Pinned 2001:db8:4000::/56 (entered)', pd_bearer: '2001:db8:4000::/64',
      pd_delegated: '2001:db8:4000:80::/57', pd_router: '02:00:5e:10:20:30',
      pd_health: 'Healthy. Router has a current advertisement and the delegated prefix matches the pin.',
      pd_last_action: 'periodic router advertisement (unix 1790953440)',
      nat_enabled: true, nat_mode: 'separate', custom_mtu: false, mtu: 1500, name: unit.name, hostname: '',
    },
    actions: [{id: 'mode.save', kind: 'save', label: 'Save changes', confirm: 'Applying these settings may interrupt connectivity.'}],
  },
  ssh: {
    groups: [
      {id: 'service', title: 'Shell service', description: 'SSH for the root account. Only the keys below can sign in; passwords are never accepted.'},
      {id: 'keys', title: 'Authorized keys'},
      {id: 'add', title: 'Add a key', description: 'Paste a public key, for example the contents of id_ed25519.pub. It can sign in as soon as it is added.'},
      {id: 'remove', title: 'Remove a key', description: 'Keys installed with the firmware can only be changed by reinstalling it.'},
    ],
    fields: [
      readonly('status', 'Service', 'service'), readonly('sign_in', 'Sign in', 'service'), readonly('host_key', 'Host key fingerprint', 'service'),
      {id: 'name', label: 'Name', group: 'add', type: 'text', max_length: 64, placeholder: 'Whose key this is'},
      {id: 'key', label: 'Public key', group: 'add', type: 'textarea', rows: 4, max_length: 8192, required: true},
      choice('remove', 'Key', 'remove', [
        ['SHA256:3mYc0Zs1q8dQyT5uVbN2hLr7KpXeWfGa4jRoCtIiDnM', 'NOC on-call (SHA256:3mYc0Zs1q8dQyT5uVbN2hLr7KpXeWfGa4jRoCtIiDnM)'],
        ['SHA256:Qk7LwBv9eHs2nAaXc4TzRdUy6MfPoJg1iSmE8ZtNq0o', 'Field laptop (SHA256:Qk7LwBv9eHs2nAaXc4TzRdUy6MfPoJg1iSmE8ZtNq0o)'],
      ]),
    ],
    tables: [{
      group: 'keys',
      columns: [{key: 'name', label: 'Name'}, {key: 'type', label: 'Type'}, {key: 'fingerprint', label: 'Fingerprint'}, {key: 'source', label: 'Source'}],
      rows: [
        {name: 'NOC on-call', type: 'ssh-ed25519', fingerprint: 'SHA256:3mYc0Zs1q8dQyT5uVbN2hLr7KpXeWfGa4jRoCtIiDnM', source: 'Added here'},
        {name: 'Field laptop', type: 'ssh-ed25519', fingerprint: 'SHA256:Qk7LwBv9eHs2nAaXc4TzRdUy6MfPoJg1iSmE8ZtNq0o', source: 'Added here'},
      ],
    }],
    values: {
      status: 'Running on port 2222', sign_in: 'ssh -p 2222 root@<address of this Titan>',
      host_key: 'SHA256:Wn5pJ2xUe0RkGh7CvYs9LdQa3ZbTf1MoIi8EyKu6Xcw', name: '', key: '',
      remove: 'SHA256:3mYc0Zs1q8dQyT5uVbN2hLr7KpXeWfGa4jRoCtIiDnM',
    },
    actions: [
      {id: 'ssh.add', label: 'Add key', kind: 'action', group: 'add', fields: ['name', 'key'], enabled: true, help: ''},
      {id: 'ssh.remove', label: 'Remove key', kind: 'action', group: 'remove', fields: ['remove'], enabled: true,
        confirm: 'Remove this key? It can no longer sign in. Sessions that are already open stay connected.'},
    ],
  },
};
// Tabs passed through on the way to a screenshot get an empty, valid answer.
const section = name => ({section: name, revision: 'demo', groups: [], fields: [], values: {}, actions: [], capabilities: {write: true}, ...settings[name]});

const browser = await chromium.launch();
async function open({width, height, phone = false, dark = false, signedIn = true, aim = 82, session = 76477}) {
  const context = await browser.newContext({viewport: {width, height}, deviceScaleFactor: 2, isMobile: phone, hasTouch: phone, colorScheme: dark ? 'dark' : 'light'});
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  // Only our localhost fixture server is allowed: no production API or map requests.
  await context.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
  await page.route('**/ui/device-mac.txt', route => route.fulfill({body: unit.mac}));
  const demo = {aim, samples: 0};
  await page.clock.install({time: new Date('2026-10-15T15:04:00Z')});
  if (dark) await page.addInitScript(() => localStorage.setItem('titan-demo-dark', 'true'));
  await page.route('**/api/v1/**', route => {
    const path = new URL(route.request().url()).pathname;
    if (!signedIn) return route.fulfill({status: 401, json: {error: 'unauthorized'}});
    if (path === '/api/v1/session') return route.fulfill({json: {authenticated: true, csrf_token: 'demo'}});
    if (path === '/api/v1/telemetry') {
      const n = ++demo.samples;
      const reading = signal(demo.aim, n);
      const dl = (54 + 14 * Math.sin(n / 8)) * 1e6, ul = (7 + 2 * Math.sin(n / 6)) * 1e6;
      const carrier = (index, offset) => ({index,role:index?'scc':'pcc',earfcn:55990 + offset,pci:190 + index,band:48,bandwidth_mhz:20,dl_mcs:21,dl_modulation:'64QAM',rsrp:reading.rsrp-index,sinr:reading.sinr-index,active:true,state:'Active'});
      return route.fulfill({json: {sequence: n, age_ms: 0, stale: false, telemetry: {...unit, ...reading, session: session + n,
        throughput:{dl_bps:dl,ul_bps:ul},gps:{fix:false},
        radio:{age_ms:0,active_chains:2,configured_carriers:2,active_carriers:2,cqi:12,ri:2,mimo:'2×2',carriers:[carrier(0,0),carrier(1,200)],
          dl:{modulation:'64QAM',mcs:21},ul:{modulation:'16QAM',mcs:15},
          signal:{seq:n,reading:n,age_ms:0,reading_age_ms:0,sampled_unix_ms:1792076640000+n*1000,rsrp:reading.chains,rsrq:[reading.rsrq,reading.rsrq-.4],rssi:[-58,-59],period_ms:1000},
          quality:{seq:n,age_ms:0,sampled_unix_ms:1792076640000+n*1000,cinr:[reading.sinr,reading.sinr-.8],sinr:reading.sinr,sinr_step_db:1}}
      }}});
    }
    if (path === '/api/v1/history') {
      const now = 1792076640000 + demo.samples * 1000;
      const points = Array.from({length:120},(_,i)=>({t:now-(119-i)*5000,dl:(54+14*Math.sin(i/8))*1e6,ul:(7+2*Math.sin(i/6))*1e6,sinr:23+Math.sin(i/10),rsrp:-82+Math.sin(i/9),carriers:2}));
      return route.fulfill({json:{points,oldest_unix_ms:now-600000,summary:{dl_avg:54000000,dl_peak:68000000,ul_avg:7000000,ul_peak:9000000,sinr_avg:23,rsrp_avg:-82,rsrq_avg:-9}}});
    }
    if (path.startsWith('/api/v1/settings/')) return route.fulfill({json: section(path.split('/').at(-1))});
    return route.fulfill({status: 404, json: {error: 'not in the demo'}});
  });
  // One second of the panel's clock, and the telemetry sample that second asks for.
  const seconds = async count => {
    for (let i = 0; i < count; i++) {
      const before = demo.samples;
      await page.clock.runFor(1000);
      for (let waited = 0; signedIn && demo.samples === before && waited < 40; waited++) await page.waitForTimeout(5);
      await page.waitForTimeout(15);
    }
  };
  // A desktop shot is the whole page, or its top `crop` pixels. The sidebar is
  // as tall as the window, so the window grows to the page instead of stitching.
  const shot = async (name, {crop, type = 'png'} = {}) => {
    if (!phone) await page.setViewportSize({width, height: crop ?? await page.evaluate(() => document.documentElement.scrollHeight)});
    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(350);
    // The page keeps a gutter for a scrollbar that a screenshot does not have.
    const clip = {x: 0, y: 0, ...await page.evaluate(() => ({width: document.body.getBoundingClientRect().right, height: innerHeight}))};
    const file = name + (type === 'jpeg' ? '.jpg' : '.png');
    await page.screenshot({path: resolve(here, file), animations: 'disabled', clip, type, ...(type === 'jpeg' ? {quality: 86} : {})});
    if (errors.length) throw Error(errors.join('\n'));
    console.log(file);
  };
  return {page, demo, seconds, shot, close: () => context.close()};
}
// Use the same long-running demo identity on desktop and phone.
const desktop = {width: 1280, height: 800}, phone = {width: 390, height: 844, phone: true};

async function overview(name, view) {
  const {page, seconds, shot, close} = await open(view);
  await page.goto(origin + '/ui/#overview');
  await page.getByRole('heading', {name: 'Overview', exact: true}).waitFor();
  await seconds(12);
  await page.locator('[data-range=\"10m\"]').click();
  await seconds(2);
  await shot(name);
  await close();
}
// Three antenna positions, then back to the best one, the way a tech uses it.
async function align(name, view) {
  const {page, demo, seconds, shot, close} = await open({...view, aim: 52});
  await page.goto(origin + '/ui/#align');
  await page.getByRole('heading', {name: 'Antenna alignment', exact: true}).waitFor();
  await seconds(8);
  for (const [index, aim] of [52, 84, 68].entries()) {
    demo.aim = aim;
    await seconds(4);
    await page.locator('[data-align-steps] [data-step=peak]').click();
    await page.locator('[data-action=mark]').click();
    await seconds(7);
    await page.locator('.position').filter({hasText: 'Position ' + (index + 1)}).waitFor();
  }
  demo.aim = 84;
  await seconds(40);
  await shot(name);
  await close();
}
async function tab(name, view, steps, ready, crop) {
  const {page, seconds, shot, close} = await open(view);
  await page.goto(origin + '/ui/#overview');
  await page.getByRole('heading', {name: 'Overview', exact: true}).waitFor();
  for (const [role, label] of steps) {
    const target = role === 'nav' ? page.locator(view.phone ? '.mobile-nav' : '.side-nav').getByText(label, {exact: true}) : page.getByRole('tab', {name: label, exact: true});
    await target.click();
    await seconds(1);
  }
  await page.locator(`[data-settings-ready][data-settings-tab="${ready}"]`).waitFor();
  await seconds(2);
  await shot(name, {crop});
  await close();
}
async function login(name, view) {
  const {page, shot, close} = await open({...view, signedIn: false});
  await page.goto(origin + '/ui/');
  await page.locator('#login-password').waitFor();
  await page.clock.runFor(1000);
  await shot(name, {crop: view.height, type: 'jpeg'});
  await close();
}

await login('login', desktop);
await overview('overview', desktop);
await overview('overview-dark', {...desktop, dark: true});
await align('align', desktop);
await tab('ipv6', desktop, [['nav', 'Network']], 'mode', 1040);
await tab('ssh-keys', desktop, [['nav', 'System'], ['tab', 'Access'], ['tab', 'SSH keys']], 'ssh', 1236);
await overview('phone-overview', phone);
await align('phone-align', phone);
await tab('phone-network', phone, [['nav', 'Network']], 'mode');

await browser.close();
server.close();
