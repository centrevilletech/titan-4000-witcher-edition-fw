// Read-only browser benchmark. Only authentication may POST; no settings writes.
// Output contains timing/path/status only, never cookies or request/response bodies.
import {chromium,expect} from '@playwright/test';
import {writeFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
const base=process.env.TITAN_URL||'http://127.0.0.1:18482';
if(!process.env.TITAN_PASSWORD)throw new Error('Set TITAN_PASSWORD for the bench unit.');
const browser=await chromium.launch({headless:true});
const report={base,measured_at:new Date().toISOString(),stages:[],requests:[],errors:[]};
let stage='cold-entry';const started=performance.now(),inflight=new Map();
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000},ignoreHTTPSErrors:process.env.TITAN_INSECURE_TLS==='1'});
 page.on('pageerror',e=>report.errors.push(e.message));
 await page.route('**/*',route=>{
  const r=route.request(),path=new URL(r.url()).pathname;
  if(/\.(asp|cgi)(?:$|\/)/i.test(path)||r.resourceType()==='document'&&r.frame().parentFrame()||r.method()!=='GET'&&!(r.method()==='POST'&&path==='/api/v1/session')){report.errors.push(`Blocked unexpected write: ${r.method()} ${path}`);return route.abort();}
  return route.continue();
 });
 page.on('request',r=>inflight.set(r,{stage,path:new URL(r.url()).pathname,method:r.method(),type:r.resourceType(),start_ms:Math.round(performance.now()-started)}));
 page.on('requestfinished',async r=>{const item=inflight.get(r);if(!item)return;item.duration_ms=Math.round(performance.now()-started-item.start_ms);const response=await r.response();item.status=response?.status();const headers=response?.headers();item.cache_control=headers?.['cache-control'];item.etag=headers?.etag;report.requests.push(item);inflight.delete(r);});
 page.on('requestfailed',r=>{const item=inflight.get(r);if(item){item.failed=true;report.requests.push(item);inflight.delete(r);}});
 let begin=performance.now();await page.goto(base+'/',{waitUntil:'domcontentloaded'});
 await expect(page.locator('#login-password').or(page.locator('h1')).first()).toBeVisible({timeout:30000});
 report.stages.push({stage,elapsed_ms:Math.round(performance.now()-begin)});
 if(await page.locator('#login-password').isVisible()){
  stage='sign-in';begin=performance.now();await page.locator('#login-password').fill(process.env.TITAN_PASSWORD);
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await expect(page.locator('h1')).toHaveText('Overview',{timeout:45000});
  report.stages.push({stage,elapsed_ms:Math.round(performance.now()-begin)});
 }
 report.serial=await page.locator('[data-device=serial]').first().innerText();
 if(process.env.TITAN_SERIAL)assert.equal(report.serial,process.env.TITAN_SERIAL);
 stage='authenticated-reload';begin=performance.now();await page.reload({waitUntil:'domcontentloaded'});
 await expect(page.locator('h1')).toHaveText('Overview',{timeout:30000});
 await expect(page.locator('[data-live=sinr]').first()).not.toHaveText('—',{timeout:15000});
 report.stages.push({stage,elapsed_ms:Math.round(performance.now()-begin)});
 stage='alignment';begin=performance.now();await page.locator('.side-nav').getByText('Align',{exact:true}).click();
 await expect(page.locator('h1')).toHaveText('Antenna alignment');
 await expect(page.locator('[data-live=sinr]').first()).not.toHaveText('—');
 report.stages.push({stage,elapsed_ms:Math.round(performance.now()-begin)});
 await page.waitForTimeout(6000);
 if(process.env.TITAN_SCREENSHOT)await page.screenshot({path:process.env.TITAN_SCREENSHOT,fullPage:true});
 stage='apn-settings';begin=performance.now();await page.locator('.side-nav').getByText('Radio',{exact:true}).click();
 await expect(page.locator('[data-native-host] [data-control]').first()).toBeVisible({timeout:30000});
 report.stages.push({stage,elapsed_ms:Math.round(performance.now()-begin)});
 assert.deepEqual(report.errors,[]);
}finally{
 await browser.close();
 const output=JSON.stringify(report,null,2)+'\n';
 if(process.env.TITAN_REPORT)await writeFile(process.env.TITAN_REPORT,output,{mode:0o600});
 console.log(output);
}
