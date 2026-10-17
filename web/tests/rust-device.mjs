import {chromium,expect} from '@playwright/test';
import {createServer} from 'vite';
import assert from 'node:assert/strict';
import {sample,signalBlock,qualityBlock,radioBlock} from './fixtures/telemetry.mjs';

const server=await createServer({mode:'rust-device',server:{host:'127.0.0.1',port:4192,strictPort:true,watch:null,hmr:false}});
await server.listen();
const browser=await chromium.launch({headless:true});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 const errors=[],legacyTelemetry=[],writes=[];let authenticated=true,sequence=1,advance=false,readings=true,stale=false,age=0,polls=0;
 // Broker watch state: ages grow from the last change, as on the device.
 const watch={seq:1,reading:1,quality:1,changed:Date.now(),qualityAt:Date.now()};
 page.on('pageerror',e=>errors.push(e.message));
 page.on('request',r=>{if(r.url().includes('telemetry.asp'))legacyTelemetry.push(r.url());});
 await page.route('**/api/v1/session',async route=>{
  const method=route.request().method();
  if(method==='POST'){assert.deepEqual(route.request().postDataJSON(),{password:'fixture-password'});authenticated=true;writes.push(method);}
  if(method==='DELETE'){assert.equal(route.request().headers()['x-csrf-token'],'fixture-token');authenticated=false;writes.push(method);await route.fulfill({status:204});return;}
  await route.fulfill({status:authenticated?200:401,json:authenticated?{authenticated:true,csrf_token:'fixture-token'}:{error:'unauthorized'}});
 });
 await page.route('**/api/v1/telemetry',async route=>{
  if(!authenticated){await route.fulfill({status:401,json:{error:'unauthorized'}});return;}
  const now=Date.now();
  if(advance){sequence++;polls++;if(readings){watch.seq++;watch.reading++;watch.changed=now;if(polls%2===0){watch.quality++;watch.qualityAt=now;}}}
  const radio=radioBlock({signal:signalBlock({seq:watch.seq,reading:watch.reading,age_ms:now-watch.changed,reading_age_ms:now-watch.changed}),quality:qualityBlock({seq:watch.quality,age_ms:now-watch.qualityAt})});
  await route.fulfill({json:sample({sequence,age_ms:age,stale,radio})});
 });
 const mark=()=>page.getByRole('button',{name:'Mark this position',exact:true});
 await page.goto('http://127.0.0.1:4192/ui/#align');
 await expect(page.locator('h1')).toHaveText('Antenna alignment');
 await expect(page.locator('[data-live=sinr]')).toHaveText('18.6');
 assert.equal(await page.locator('[data-gauge]').count(),2);
 assert.equal(await page.locator('[data-action=mark]').count(),1);
 await expect(page.locator('[data-live=pci]')).toHaveText('190');
 // A frozen collector never completes a mark: the label counts readings, not seconds.
 await mark().click();
 await page.waitForTimeout(6100);
 await expect(page.locator('.position')).toHaveCount(0);
 await expect(page.locator('[data-freshness]')).toHaveText(/Titan polled [67]s ago/);
 await expect(page.getByRole('button',{name:'Hold still · reading 0 of 3',exact:true})).toBeDisabled();
 await expect(page.locator('[data-live=sinr]')).toHaveText('—',{timeout:5000});
 await expect(page.locator('.position')).toHaveCount(0);
 // Three distinct readings complete a position even with identical values.
 advance=true;
 await expect(page.locator('[data-live=sinr]')).toHaveText('18.6');
 await mark().click();
 await expect(page.locator('.position')).toHaveCount(1,{timeout:9000});
 // The envelope advancing alone is not a new modem reading.
 readings=false;
 await page.waitForTimeout(1500);
 await mark().click();
 await page.waitForTimeout(12000);
 await expect(page.locator('.position')).toHaveCount(1);
 await expect(page.getByRole('button',{name:'Hold still · reading 0 of 3',exact:true})).toBeDisabled();
 await page.locator('[data-align-action=cancel]').click();
 readings=true;
 stale=true;
 await expect(page.locator('[data-live=sinr]')).toHaveText('—');
 await expect(mark()).toBeDisabled();
 stale=false;age=9000;
 await page.waitForTimeout(1200);
 await expect(page.locator('[data-live=sinr]')).toHaveText('—');
 age=0;
 await expect(page.locator('[data-live=sinr]')).toHaveText('18.6');
 const download=page.waitForEvent('download');await page.getByRole('button',{name:'Export',exact:true}).click();
 assert.equal((await download).suggestedFilename(),'titan-alignment.csv');
 authenticated=false;
 await expect(page.locator('#login-password')).toBeVisible();
 await page.locator('#login-password').fill('fixture-password');
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.locator('h1')).toHaveText('Overview');
 await page.getByRole('button',{name:'Sign out',exact:true}).click();
 await expect(page.locator('#login-password')).toBeVisible();
 assert.equal(await page.evaluate(()=>JSON.stringify(localStorage).includes('fixture-password')),false);
 assert.deepEqual(writes,['POST','DELETE']);assert.deepEqual(legacyTelemetry,[]);assert.deepEqual(errors,[]);
 // An older backend without radio.signal still drives the screen from value changes.
 const legacy=await browser.newPage({viewport:{width:390,height:844}}),legacyErrors=[];let legacySequence=1;
 legacy.on('pageerror',e=>legacyErrors.push(e.message));
 await legacy.route('**/api/v1/session',route=>route.fulfill({json:{authenticated:true,csrf_token:'fixture-token'}}));
 await legacy.route('**/api/v1/telemetry',route=>{const s=sample({sequence:++legacySequence});s.telemetry.chains=[-84.2,-85.1-(legacySequence%3)/10];return route.fulfill({json:s});});
 await legacy.goto('http://127.0.0.1:4192/ui/#align');
 await expect(legacy.locator('h1')).toHaveText('Antenna alignment');
 await expect(legacy.locator('[data-live=sinr]')).toHaveText('18.6');
 await expect(legacy.locator('[data-live=rsrp]')).not.toHaveText('—');
 await expect(legacy.locator('[data-action=mark]')).toBeEnabled();
 assert.deepEqual(legacyErrors,[]);
 console.log('PASS: Rust JSON UI, reading-counted marks (frozen collector, envelope-only changes), source age/stale state, legacy telemetry fallback, live CSV, auth expiry/login and CSRF logout; no legacy telemetry requests.');
}finally{await browser.close();await server.close();}
