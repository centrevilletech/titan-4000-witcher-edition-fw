// Bench telemetry test. No configuration writes; credential stays in process memory.
import {chromium,expect} from '@playwright/test';
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
const base=process.env.TITAN_URL||'http://127.0.0.1:18482';
const telemetryPath='**/api/v1/telemetry';
if(!process.env.TITAN_PASSWORD)throw new Error('Set TITAN_PASSWORD for a bench unit.');
const browser=await chromium.launch({headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000},ignoreHTTPSErrors:process.env.TITAN_INSECURE_TLS==='1'});
const errors=[],writes=[];page.on('pageerror',e=>errors.push(e.stack));page.on('request',r=>{if(r.method()!=='GET')writes.push(r.method()+':'+new URL(r.url()).pathname);});
await page.route('**/*',route=>{const r=route.request(),path=new URL(r.url()).pathname;if(/\.(asp|cgi)(?:$|\/)/i.test(path)||r.resourceType()==='document'&&r.frame().parentFrame()||r.method()!=='GET'&&!(r.method()==='POST'&&path==='/api/v1/session')){errors.push('Forbidden request '+r.method()+' '+path);return route.abort();}return route.continue();});
await page.goto(base+'/ui/index.html');await expect(page.locator('#login-password')).toBeVisible();
await page.locator('#login-password').fill(process.env.TITAN_PASSWORD);await page.getByRole('button',{name:'Sign in',exact:true}).click();
await expect(page.locator('h1')).toHaveText('Overview',{timeout:30000});
const serial=await page.locator('[data-device=serial]').first().innerText();
assert.match(serial,/^GLOBAL\d+$/);if(process.env.TITAN_SERIAL)assert.equal(serial,process.env.TITAN_SERIAL);
await expect(page.locator('.edition')).toHaveText(/^Witcher v/);
await expect(page.locator('[data-live=rsrp]')).not.toHaveText('—');
console.log('Authenticated live overview:',serial,'firmware and telemetry present');
// Full custom settings coverage lives in live-refinement.mjs.
await page.locator('.side-nav').getByText('Align',{exact:true}).click();await expect(page.locator('[data-gauge]')).toHaveCount(2);
await expect(page.locator('[data-live=sinr]').first()).not.toHaveText('—');
await page.getByRole('button',{name:'Mark this position',exact:true}).last().click();await expect(page.locator('.position')).toHaveCount(1,{timeout:40000});
console.log('Live alignment captured a three-reading position');
if(process.env.TITAN_FAILURE_TEST==='1'){
 await page.route(telemetryPath,route=>route.abort());await page.waitForTimeout(9500);
 await expect(page.locator('[data-live=sinr]').first()).toHaveText('—');
 await expect(page.getByRole('button',{name:'Mark this position',exact:true}).last()).toBeDisabled();
 await page.unroute(telemetryPath);await expect(page.locator('[data-live=sinr]').first()).not.toHaveText('—',{timeout:15000});
 await page.setViewportSize({width:390,height:844});await page.screenshot({path:'/tmp/titan-live-align-phone.png',fullPage:true});
 console.log('PASS: interrupted browser telemetry goes stale, blocks capture and recovers');
}
// An external bench controller pauses/restores only the read-only sampler.
// This browser script never changes processes or the physical radio itself.
if(process.env.TITAN_COLLECTOR_MARKER){
 const marker=process.env.TITAN_COLLECTOR_MARKER;
 await writeFile(marker,'ready\n',{mode:0o600});console.log('READY: waiting for external collector outage');
 await expect(page.locator('[data-live=sinr]').first()).toHaveText('—',{timeout:60000});
 await expect(page.getByRole('button',{name:'Mark this position',exact:true}).last()).toBeDisabled();
 await writeFile(marker,'stale\n');console.log('STALE: collector failure disables alignment; restore collector');
 await expect(page.locator('[data-live=sinr]').first()).not.toHaveText('—',{timeout:60000});
 await expect(page.getByRole('button',{name:'Mark this position',exact:true}).last()).toBeEnabled();
 await writeFile(marker,'recovered\n');console.log('PASS: actual collector outage and recovery reflected in browser');
}

assert.deepEqual(writes,['POST:/api/v1/session'],'Reading pages must not submit settings');
assert.deepEqual(errors,[]);console.log('PASS: real telemetry, stale recovery and alignment; no JS errors');
await browser.close();
