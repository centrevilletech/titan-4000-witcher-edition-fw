// Dashboard data, stale readings, history failures and re-entry in the device UI.
import {chromium,expect} from '@playwright/test';
import {createServer} from 'vite';
import {sample} from './fixtures/telemetry.mjs';
const server=await createServer({mode:'rust-device',server:{host:'127.0.0.1',port:0,watch:null,hmr:false}});
await server.listen();
const base=`http://127.0.0.1:${server.httpServer.address().port}`;
const browser=await chromium.launch();
try{
 for(const width of [1440,390,320]){
  const page=await browser.newPage({viewport:{width,height:1000},reducedMotion:'reduce'});
  const errors=[];let sequence=0,stale=false,failHistory=false;
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/v1/session',r=>r.fulfill({json:{authenticated:true,csrf_token:'fixture'}}));
  await page.route('**/api/v1/settings/**',r=>r.fulfill({status:404,json:{error:'unavailable'}}));
  await page.route('**/api/v1/telemetry',r=>{
   const next=sample({sequence:++sequence,stale});
   next.telemetry.throughput={dl_bps:12500000,ul_bps:2500000};
   return r.fulfill({json:next});
  });
  await page.route('**/api/v1/history?*',r=>r.fulfill(failHistory?{status:503,json:{error:'unavailable'}}:{json:{points:[{t:Date.now(),dl:12500000,ul:2500000,sinr:18.6,rsrp:-84.2}],summary:{dl_avg:12500000,dl_peak:12500000,ul_avg:2500000,ul_peak:2500000,sinr_avg:18.6,rsrp_avg:-84.2},oldest_unix_ms:Date.now()-3600000}}));
  await page.goto(base+'/ui/#overview');
  await expect(page.locator('[data-speedo=dl] [data-speedo-text]')).toHaveText('12.5');
  await expect(page.locator('[data-speedo=ul] [data-speedo-text]')).toHaveText('2.50');
  await page.locator('[data-range="10m"]').click();
  await expect(page.locator('[data-history-note]')).toHaveText('Stored on the Titan');
  await expect(page.locator('[data-speed-window]')).toHaveText('Last 10 min');
  stale=true;
  await expect(page.locator('[data-speedo=dl] [data-speedo-text]')).toHaveText('—');
  await expect(page.locator('[data-link-quality]')).toHaveText('Waiting for signal');
  failHistory=true;
  await page.locator('[data-range="1h"]').click();
  await expect(page.locator('[data-history-note]')).toHaveText('History unavailable');
  stale=false;
  await expect(page.locator('[data-speedo=dl] [data-speedo-text]')).toHaveText('12.5');
  await page.goto(base+'/ui/#align');
  await expect(page.locator('h1')).toHaveText('Antenna alignment');
  await page.goto(base+'/ui/#overview');
  await expect(page.locator('[data-speedo]')).toHaveCount(2);
  await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  expect(errors).toEqual([]);
  await page.close();
 }
 console.log('PASS: live speedometers, history selection/failure, stale data, recovery and page re-entry at desktop/390/320 widths.');
}finally{await browser.close();await server.close();}
