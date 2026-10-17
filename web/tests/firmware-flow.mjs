// Real desktop UI, simulated devices only: no firmware bytes leave this host.
import {chromium,expect} from '@playwright/test';
import {createServer} from 'vite';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {settingsFixtures} from './fixtures/settings.mjs';
import {sample} from './fixtures/telemetry.mjs';
const version=readFileSync(new URL('../../VERSION',import.meta.url),'utf8').trim();
const server=await createServer({mode:'rust-device',server:{host:'127.0.0.1',port:4198,strictPort:true,watch:null,hmr:false}});
await server.listen();const browser=await chromium.launch({headless:true});
try {
 for(const mode of ['success','lost-response','expired-operation','rejected','no-restart']){
  const page=await browser.newPage(),fixtures=settingsFixtures(),errors=[];
  let posts=0,sequence=0,boot='before',finished=false,phase='idle',polls=0;
  fixtures.firmware.values.boot_id=boot;
  fixtures.firmware.values.reboot=mode!=='no-restart';
  fixtures.firmware.fields.push({id:'reboot',label:'Restart after installation',type:'checkbox',group:'local'});
  fixtures.firmware.actions[0].fields.push('reboot');
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/ui/device-mac.txt',r=>r.fulfill({body:'02:00:5e:40:00:01'}));
  await page.route('**/api/v1/**',async r=>{
   const req=r.request(),path=new URL(req.url()).pathname;
   if(path==='/api/v1/health')return r.fulfill({json:{service:'titan-api',boot_id:boot}});
   if(path==='/api/v1/session')return r.fulfill({status:finished?401:200,json:finished?{error:'expired'}:{authenticated:true,csrf_token:'fixture'}});
   if(path==='/api/v1/telemetry')return r.fulfill({status:finished?401:200,json:finished?{error:'expired'}:sample({sequence:++sequence})});
   if(path.startsWith('/api/v1/settings/'))return r.fulfill({json:fixtures[path.split('/').at(-1)]});
   if(path==='/api/v1/history')return r.fulfill({json:{window:'30s',step_ms:1000,now_unix_ms:Date.now(),points:[],summary:null}});
   if(path==='/api/v1/uploads/firmware.install'){
    posts++;phase='upload';assert.equal(req.method(),'POST');
    if(mode==='rejected')return r.fulfill({status:400,json:{error:'Image checksum does not match.'}});
    if(mode==='lost-response'){phase='waiting';return r.abort('connectionreset');}
    return r.fulfill({status:202,json:{operation:{id:'upgrade',state:'running',message:'Installing and verifying firmware…'}}});
   }
   if(path==='/api/v1/operations/upgrade'){
    polls++;
    if(mode==='expired-operation'){phase='waiting';return r.fulfill({status:401,json:{error:'expired'}});}
    if(polls===1)return r.fulfill({json:{operation:{id:'upgrade',state:'running',message:'Verifying installed firmware…'}}});
    phase='waiting';return r.fulfill({json:{operation:{id:'upgrade',state:'succeeded',rebooting:mode!=='no-restart',message:'Verified.'}}});
   }
   return r.fulfill({status:404,json:{error:'Unavailable in fixture'}});
  });
  await page.goto('http://127.0.0.1:4198/ui/');
  await expect(page.locator('h1')).toHaveText('Overview');
  await page.locator('.side-nav').getByText('System',{exact:true}).click();
  await page.getByRole('tab',{name:'Firmware',exact:true}).click();
  await page.getByLabel('Firmware file',{exact:true}).setInputFiles({name:'fixture.prg',mimeType:'application/octet-stream',buffer:Buffer.from('FIXTURE ONLY')});
  await page.getByRole('button',{name:'Upgrade firmware',exact:true}).click();
  await page.getByRole('button',{name:'Continue',exact:true}).click();
  if(mode==='rejected'){
   await expect(page.locator('.device-error')).toContainText('Image checksum does not match.');
   assert.equal(new URL(page.url()).searchParams.has('witcher_reload'),false);
  }else if(mode==='no-restart'){
   await expect(page.locator('#toast')).toContainText('Verified.');
   await expect(page.locator('[data-settings-ready]')).toBeVisible();
   assert.equal(new URL(page.url()).searchParams.has('witcher_reload'),false);
  }else{
   await expect(page.locator('[data-reconnect-status]')).toBeVisible({timeout:10000});
   await expect.poll(()=>phase).toBe('waiting');
   // Same boot must not be called success, even while health returns HTTP 200.
   await page.waitForTimeout(3300);
   assert.equal(new URL(page.url()).searchParams.has('witcher_reload'),false);
   // Session expires during reboot. Reconnect must survive and load a new document.
   finished=true;boot='after';
   await page.waitForURL(url=>url.searchParams.has('witcher_reload'),{timeout:15000});
   await expect(page.locator('.login-version')).toHaveText('Witcher v'+version);
   await expect(page.locator('#preview-login')).toContainText('Device restarted. Now running Witcher v'+version);
  }
  assert.equal(posts,1,mode+' must never repeat the upload');assert.deepEqual(errors,[]);
  await page.close();
 }
 // A tab left on another screen/login notices a newly served firmware version.
 const page=await browser.newPage();
 await page.goto('http://127.0.0.1:4198/ui/');
 const watched=await page.evaluate(async()=>{
  const {watchFirmwareVersion}=await import('/ui/src/device/firmware-reconnect.js');
  let dirty=true,seen=null;
  const stop=watchFirmwareVersion('old',{interval:20,canReload:()=>!dirty,fetcher:async()=>({ok:true,text:async()=>'<meta name="witcher-version" content="1.0.0-rc.7" />'}),onChange:value=>{seen=value;}});
  await new Promise(r=>setTimeout(r,70));const whileDirty=seen;dirty=false;
  await new Promise(r=>setTimeout(r,100));stop();return {whileDirty,seen};
 });
 assert.deepEqual(watched,{whileDirty:null,seen:'1.0.0-rc.7'});await page.close();
 console.log('PASS: desktop upload/restart, lost acknowledgement, expired session, rejection, no-restart, single submission, fresh version notice, stale-tab watcher and unsaved-edit protection.');
}finally{await browser.close();await server.close();}
