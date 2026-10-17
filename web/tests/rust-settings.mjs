import {chromium,expect} from '@playwright/test';
import {createServer} from 'vite';
import assert from 'node:assert/strict';
import {settingsFixtures} from './fixtures/settings.mjs';
import {sample} from './fixtures/telemetry.mjs';

const server=await createServer({mode:'rust-device',server:{host:'127.0.0.1',port:4193,strictPort:true,watch:null,hmr:false}});
await server.listen();const browser=await chromium.launch({headless:true});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),fixtures=settingsFixtures(),errors=[],forbidden=[],mutations=[];
 let sequence=0,authenticated=true,putMode='success',polls=0,operationState='succeeded';
 page.on('pageerror',error=>errors.push(error.message));
 await page.route('**/*',route=>{
  const request=route.request(),path=new URL(request.url()).pathname;
  if(/\.(asp|cgi)(?:$|\/)/i.test(path)||request.resourceType()==='document'&&request.frame().parentFrame()){
   forbidden.push(path);return route.abort();
  }
  return route.fallback();
 });
 await page.route('**/api/v1/**',async route=>{
  const request=route.request(),path=new URL(request.url()).pathname,method=request.method();
  if(path==='/api/v1/session')return route.fulfill({status:authenticated?200:401,json:authenticated?{authenticated:true,csrf_token:'fixture-csrf'}:{error:'expired'}});
  if(path==='/api/v1/telemetry')return route.fulfill({status:authenticated?200:401,json:authenticated?sample({sequence:++sequence}):{error:'expired'}});
  if(!authenticated)return route.fulfill({status:401,json:{error:'expired'}});
  if(method!=='GET'){assert.equal(request.headers()['x-csrf-token'],'fixture-csrf');mutations.push({path,method,body:request.headers()['content-type'].includes('application/json')?request.postDataJSON():request.postData(),headers:request.headers()});}
  if(path.startsWith('/api/v1/settings/')){
   const section=path.split('/').at(-1),model=fixtures[section];assert.ok(model,'Known section '+section);
   if(method==='GET')return route.fulfill({json:model});
   assert.equal(method,'PUT');const body=request.postDataJSON();assert.equal(body.revision,model.revision);
   if(putMode==='transport')return route.abort('failed');
   if(putMode==='conflict')return route.fulfill({status:409,json:{error:'revision conflict'}});
   if(putMode==='mismatch')return route.fulfill({json:model});
   if(putMode==='pending'){polls=0;return route.fulfill({status:202,json:{operation:{id:'fixture-operation',state:'pending',message:'Applying settings'}}});}
   Object.assign(model.values,body.values);model.revision+='x';return route.fulfill({json:model});
  }
  if(path.startsWith('/api/v1/operations/')){
   polls++;return route.fulfill({json:{operation:{id:'fixture-operation',state:polls===1?'running':operationState,message:operationState==='uncertain'?'The device did not confirm the outcome.':'Operation complete'}}});
  }
  if(path.startsWith('/api/v1/actions/')){
   const action=path.split('/').at(-1),body=request.postDataJSON();assert.ok(action.startsWith(body.section+'.'));
   if(action==='ping.run')return route.fulfill({json:{operation:{id:'ping',state:'succeeded'},output:'PING fixture: 4 received',settings:fixtures.ping}});
   if(action==='scan.refresh'){fixtures.scan.tables[0].rows.push({pci:42,earfcn:56000,sinr:21});polls=0;return route.fulfill({status:202,json:{operation:{id:'fixture-operation',state:'pending'}}});}
   if(action==='ssh.add'){
    assert.deepEqual(Object.keys(body.values).sort(),['key','name']);const print='SHA256:fixtureAdded';
    fixtures.ssh.tables[0].rows.push({name:body.values.name,type:body.values.key.split(' ')[0],fingerprint:print,source:'Added here'});
    fixtures.ssh.fields.find(f=>f.id==='remove').options.push({value:print,label:body.values.name+' ('+print+')'});fixtures.ssh.revision+='x';
    return route.fulfill({json:{operation:{id:'done',state:'succeeded',message:'Key added: '+body.values.name+' ('+print+').'},settings:fixtures.ssh}});
   }
   if(action==='ssh.remove'){
    assert.deepEqual(Object.keys(body.values),['remove']);const options=fixtures.ssh.fields.find(f=>f.id==='remove').options;
    fixtures.ssh.tables[0].rows=fixtures.ssh.tables[0].rows.filter(row=>row.fingerprint!==body.values.remove);options.splice(options.findIndex(o=>o.value===body.values.remove),1);
    fixtures.ssh.values.remove=options[0]?.value??'';fixtures.ssh.revision+='x';
    return route.fulfill({json:{operation:{id:'done',state:'succeeded',message:'Key removed.'},settings:fixtures.ssh}});
   }
   return route.fulfill({json:{operation:{id:'done',state:'succeeded'},settings:fixtures[body.section]}});
  }
  if(path.startsWith('/api/v1/uploads/')){
   assert.match(request.headers()['content-type'],/^multipart\/form-data; boundary=/);
   const body=request.postData();assert.match(body,/name="section"\r\n\r\nbackup/);assert.match(body,/name="revision"/);assert.match(body,/filename="fixture-backup.bin"/);assert.match(body,/FIXTURE-ONLY/);
   return route.fulfill({json:{operation:{id:'upload',state:'succeeded',message:'Restore complete'},settings:fixtures.backup}});
  }
  if(path==='/api/v1/downloads/backup.export')return route.fulfill({status:200,contentType:'application/octet-stream',headers:{'Content-Disposition':'attachment; filename="titan-backup.bin"'},body:'FIXTURE-BACKUP'});
  if(path==='/api/v1/history'&&method==='GET')return route.fulfill({json:{window:new URL(request.url()).searchParams.get('window'),step_ms:1000,now_unix_ms:Date.now(),oldest_unix_ms:null,points:[],summary:null}});
  if(path==='/api/v1/diagnostics'&&method==='GET')return route.fulfill({json:{tools:['ping','traceroute'],interfaces:[{value:'',label:'Automatic'},{value:'br0',label:'br0 (10.1.1.1)'}],limits:{ping:{count_max:1000,size_max:1472,ttl_max:255},traceroute:{hops_max:64,probes_max:5,wait_max:10}}}});
  if(path.startsWith('/api/v1/diagnostics/')){
   const tool=path.split('/').at(-1),events=tool==='ping'?[{type:'start',command:'ping -c 3 -s 56 -W 2 192.0.2.1'},{type:'line',stream:'stdout',text:'PING 192.0.2.1 (192.0.2.1): 56 data bytes'},{type:'line',stream:'stdout',text:'64 bytes from 192.0.2.1: seq=0 ttl=60 time=21.500 ms'},{type:'line',stream:'stdout',text:'64 bytes from 192.0.2.1: seq=2 ttl=60 time=24.500 ms'},{type:'line',stream:'stdout',text:''},{type:'line',stream:'stdout',text:'--- 192.0.2.1 ping statistics ---'},{type:'line',stream:'stdout',text:'3 packets transmitted, 2 packets received, 33% packet loss'},{type:'line',stream:'stdout',text:'round-trip min/avg/max = 21.500/23.000/24.500 ms'},{type:'end',exit_code:0,reason:'completed'}]
    :[{type:'start',command:'traceroute -n -I 192.0.2.1'},{type:'line',stream:'stdout',text:'traceroute to 192.0.2.1 (192.0.2.1), 30 hops max, 38 byte packets'},{type:'line',stream:'stdout',text:' 1  10.0.0.1  1.234 ms  1.100 ms  1.050 ms'},{type:'rdns',address:'10.0.0.1',name:'gw.fixture.example'},{type:'line',stream:'stdout',text:' 2  *  *  *'},{type:'heartbeat'},{type:'line',stream:'stdout',text:' 3  192.0.2.1  20.1 ms  20.4 ms  !H'},{type:'rdns',address:'192.0.2.1',name:null},{type:'end',exit_code:0,reason:'completed'}];
   return route.fulfill({status:200,contentType:'application/x-ndjson',body:events.map(e=>JSON.stringify(e)).join('\n')+'\n'});
  }
  throw new Error('Unexpected API request '+method+' '+path);
 });
 const cases=[['Radio','APN profiles','apn'],['Radio','Band & selection','selection'],['Radio','PCI lock','lock'],['Radio','Cell scan','scan'],['Network','Operating mode','mode'],['Network','LAN & DHCP','lan'],['Network','Firewall','firewall'],['Network','Port forwards','forwards'],['Network','Routes','routes'],['System','Device','device'],['System','Access','access'],['System','SSH keys','ssh'],['System','ACS','services'],['System','SAS','sas'],['System','CPI','cpi'],['System','CBSD status','sasStatus'],['System','Backup','backup'],['System','Firmware','firmware'],['System','Restart','restart'],['Diagnostics','Network status','status']];
 async function open(id){
  const [section,tab]=cases.find(c=>c[2]===id);await page.setViewportSize({width:1440,height:1000});
  await page.locator('.side-nav').getByText(section,{exact:true}).click();
  if(['Backup','Restart'].includes(tab))await page.getByRole('tab',{name:'Device',exact:true}).click();
  if(['CPI','CBSD status'].includes(tab))await page.getByRole('tab',{name:'SAS',exact:true}).click();
  if(tab==='SSH keys')await page.getByRole('tab',{name:'Access',exact:true}).click();
  await page.getByRole('tab',{name:tab==='CPI'?'CPI installation':tab,exact:true}).click();
  await expect(page.locator('[data-settings-ready]')).toHaveAttribute('data-settings-tab',id);
 }
 await page.goto('http://127.0.0.1:4193/ui/');await expect(page.locator('h1')).toHaveText('Overview');
 for(const [,,id]of cases){
  await open(id);await expect(page.locator('iframe')).toHaveCount(0);
  for(const width of [1440,390]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,id+' overflow at '+width);}
 }
 assert.equal(mutations.length,0,'Reading every settings screen cannot mutate the device');
 await open('services');await page.getByLabel('ACS username',{exact:true}).fill('edited-user');
 await page.getByLabel('Inform interval (seconds)',{exact:true}).fill('30');
 await page.getByRole('button',{name:'Save changes',exact:true}).click();assert.equal(mutations.length,0,'Invalid range is rejected before submission');
 await page.getByLabel('Inform interval (seconds)',{exact:true}).fill('301');
 await page.getByRole('button',{name:'Save changes',exact:true}).click();
 await expect(page.locator('#toast')).toHaveText('Settings saved and read back from the Titan.');
 assert.equal(mutations.at(-1).method,'PUT');assert.equal(mutations.at(-1).body.values.username,'edited-user');assert.equal(Object.hasOwn(mutations.at(-1).body.values,'password'),false);assert.equal(Object.hasOwn(mutations.at(-1).body.values,'stun_server'),false);
 await page.getByLabel('ACS password',{exact:true}).fill('write-only-fixture');await page.getByRole('button',{name:'Save changes',exact:true}).click();
 await expect(page.getByLabel('ACS password',{exact:true})).toHaveValue('');assert.equal(mutations.at(-1).body.values.password,'write-only-fixture');assert.equal(await page.evaluate(()=>JSON.stringify(localStorage).includes('write-only-fixture')),false);
 putMode='conflict';await page.getByLabel('Inform interval (seconds)',{exact:true}).fill('302');await page.getByRole('button',{name:'Save changes',exact:true}).click();
 await expect(page.locator('.device-error')).toContainText('changed on the Titan');await expect(page.getByLabel('Inform interval (seconds)',{exact:true})).toHaveValue('302');
 await page.getByRole('button',{name:'Discard',exact:true}).click();await expect(page.getByLabel('Inform interval (seconds)',{exact:true})).toHaveValue('301');
 putMode='mismatch';await page.getByLabel('Inform interval (seconds)',{exact:true}).fill('303');await page.getByRole('button',{name:'Save changes',exact:true}).click();
 await expect(page.locator('.device-error')).toContainText('different settings');await page.getByRole('button',{name:'Discard',exact:true}).click();
 await expect(page.getByLabel('Inform interval (seconds)',{exact:true})).toHaveValue('301');
 putMode='pending';operationState='uncertain';await page.getByLabel('Inform interval (seconds)',{exact:true}).fill('304');const before=mutations.length;await page.getByRole('button',{name:'Save changes',exact:true}).click();
 await expect(page.locator('.device-error')).toContainText('did not confirm');assert.equal(mutations.length,before+1,'Uncertain operations must not be retried automatically');
 await page.getByRole('button',{name:'Discard',exact:true}).click();await expect(page.getByLabel('Inform interval (seconds)',{exact:true})).toHaveValue('301');
 putMode='transport';await page.getByLabel('Inform interval (seconds)',{exact:true}).fill('305');const networkBefore=mutations.length;await page.getByRole('button',{name:'Save changes',exact:true}).click();
 await expect(page.locator('.device-error')).toContainText('connection ended before');assert.equal(mutations.length,networkBefore+1);await page.getByRole('button',{name:'Discard',exact:true}).click();
 putMode='success';operationState='succeeded';await open('lock');await page.getByLabel('Cell Selection',{exact:true}).selectOption('2');await expect(page.getByLabel('PCI',{exact:true})).toBeVisible();
 assert.equal(await page.getByLabel(/EARFCN/).count(),0,'GDM cell lock remains PCI-only');
 await page.getByRole('button',{name:'Add entry',exact:true}).click();await expect(page.getByLabel('PCI',{exact:true})).toHaveCount(2);
 await page.getByLabel('PCI',{exact:true}).last().fill('503');await page.getByRole('button',{name:'Save changes',exact:true}).click();await expect(page.locator('[data-settings-ready]')).toHaveAttribute('data-dirty','false');
 assert.equal(mutations.at(-1).body.values.cells[1].pci,503);
 await open('scan');await page.getByRole('button',{name:'Refresh cell list',exact:true}).click();await page.getByRole('button',{name:'Cancel',exact:true}).click();const afterCancel=mutations.length;
 await page.getByRole('button',{name:'Refresh cell list',exact:true}).click();await page.getByRole('button',{name:'Continue',exact:true}).click();await expect(page.getByRole('cell',{name:'42',exact:true})).toBeVisible();assert.equal(mutations.length,afterCancel+1);
 await open('device');await page.getByLabel('Refresh interval (seconds)',{exact:true}).fill('7');
 await page.getByRole('button',{name:'Synchronize with workstation',exact:true}).click();await expect(page.locator('#toast')).toHaveText('Device response received.');
 assert.equal(mutations.at(-1).path,'/api/v1/actions/device.sync_time');assert.ok(Math.abs(mutations.at(-1).body.values.unix_seconds-Math.floor(Date.now()/1000))<5);assert.equal(Object.keys(mutations.at(-1).body.values).length,1);await expect(page.getByLabel('Refresh interval (seconds)',{exact:true})).toHaveValue('7');
 await page.getByRole('button',{name:'Discard',exact:true}).click();
 await open('backup');const downloaded=page.waitForEvent('download');await page.getByRole('button',{name:'Download backup',exact:true}).click();assert.equal((await downloaded).suggestedFilename(),'titan-backup.bin');
 await page.getByLabel('Configuration file',{exact:true}).setInputFiles({name:'fixture-backup.bin',mimeType:'application/octet-stream',buffer:Buffer.from('FIXTURE-ONLY')});
 await page.getByRole('button',{name:'Restore settings',exact:true}).click();await page.getByRole('button',{name:'Continue',exact:true}).click();await expect(page.locator('#toast')).toHaveText('Restore complete');
 assert.equal(mutations.at(-1).path,'/api/v1/uploads/backup.restore');assert.equal(await page.getByLabel('Configuration file',{exact:true}).evaluate(input=>input.files.length),0);
 await page.locator('.side-nav').getByText('Diagnostics',{exact:true}).click();await page.getByRole('tab',{name:'Ping',exact:true}).click();
 await page.getByRole('button',{name:'Start',exact:true}).click();await expect(page.locator('[data-diag-error]')).toHaveText('Enter an IP address or hostname to test.');
 await page.locator('[name=destination]').fill('192.0.2.1');await page.locator('[name=count]').fill('3');await page.getByRole('button',{name:'Start',exact:true}).click();
 await expect(page.locator('.diag-state')).toContainText('Completed');await expect(page.locator('.diag-stat').nth(1)).toContainText('2/3');await expect(page.locator('.diag-stat').nth(2)).toContainText('33');
 await expect(page.locator('.diag-miss')).toHaveCount(1);
 let streamed=mutations.at(-1);assert.equal(streamed.path,'/api/v1/diagnostics/ping');assert.deepEqual(streamed.body,{destination:'192.0.2.1',family:'ipv4',interface:'',count:3,size:56,ttl:null,timeout:2});
 await page.getByRole('tab',{name:'Traceroute',exact:true}).click();await page.locator('[name=destination]').fill('192.0.2.1');await page.getByRole('button',{name:'Start',exact:true}).click();
 await expect(page.locator('.diag-hops tbody tr')).toHaveCount(3);await expect(page.locator('[data-hop="1"] .diag-name')).toHaveText('gw.fixture.example');await expect(page.locator('[data-hop="3"]')).toHaveClass(/diag-target/);
 await expect(page.locator('.diag-meta')).toContainText('Reached 192.0.2.1 in 3 hops');
 streamed=mutations.at(-1);assert.equal(streamed.path,'/api/v1/diagnostics/traceroute');assert.equal(streamed.body.resolve,true);assert.equal(streamed.body.protocol,'icmp');
 await page.getByRole('tab',{name:'Ping',exact:true}).click();await expect(page.locator('.diag-stat').nth(1)).toContainText('2/3');
 await open('ssh');await expect(page.getByRole('cell',{name:'SHA256:fixtureInstalledKey',exact:true})).toBeVisible();await expect(page.getByRole('cell',{name:'Installed with firmware',exact:true})).toBeVisible();
 await expect(page.getByText('SHA256:fixtureHostKey',{exact:true})).toBeVisible();await expect(page.getByRole('button',{name:'Save changes',exact:true})).toHaveCount(0);
 const beforeEmptyKey=mutations.length;await page.getByRole('button',{name:'Add key',exact:true}).click();assert.equal(mutations.length,beforeEmptyKey,'An empty public key is not submitted');
 await page.getByLabel('Name',{exact:true}).fill('Field laptop');await page.getByLabel('Public key',{exact:true}).fill('ssh-ed25519 AAAAfixture field@laptop');
 await page.getByRole('button',{name:'Add key',exact:true}).click();await expect(page.locator('#toast')).toHaveText('Key added: Field laptop (SHA256:fixtureAdded).');
 assert.equal(mutations.at(-1).path,'/api/v1/actions/ssh.add');assert.equal(mutations.at(-1).body.section,'ssh');assert.deepEqual(mutations.at(-1).body.values,{name:'Field laptop',key:'ssh-ed25519 AAAAfixture field@laptop'});
 await expect(page.getByRole('cell',{name:'Field laptop',exact:true})).toBeVisible();await expect(page.getByLabel('Public key',{exact:true})).toHaveValue('');await expect(page.locator('[data-settings-ready]')).toHaveAttribute('data-dirty','false');
 await page.getByLabel('Key',{exact:true}).selectOption('SHA256:fixtureAdded');await page.getByRole('button',{name:'Remove key',exact:true}).click();await page.getByRole('button',{name:'Cancel',exact:true}).click();const beforeRemove=mutations.length;
 await page.getByRole('button',{name:'Remove key',exact:true}).click();await page.getByRole('button',{name:'Continue',exact:true}).click();await expect(page.locator('#toast')).toHaveText('Key removed.');
 assert.equal(mutations.length,beforeRemove+1);assert.deepEqual(mutations.at(-1).body.values,{remove:'SHA256:fixtureAdded'});await expect(page.getByRole('cell',{name:'Field laptop',exact:true})).toHaveCount(0);
 await expect(page.getByRole('cell',{name:'NOC laptop',exact:true})).toBeVisible();
 authenticated=false;await open('access').catch(()=>{});await expect(page.locator('#login-password')).toBeVisible();
 assert.deepEqual(errors,[]);assert.deepEqual(forbidden,[]);await expect(page.locator('iframe')).toHaveCount(0);
 console.log('PASS: all 21 JSON settings, unchanged desktop/phone layout, no vendor requests/iframes, revisions/conflicts, secret-safe saves, readback mismatch, uncertain operations, PCI list, scan confirmation, binary download, multipart upload, SSH key add/remove and auth expiry.');
}finally{await browser.close();await server.close();}
