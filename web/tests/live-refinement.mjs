import {chromium,expect} from '@playwright/test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
if(!process.env.TITAN_PASSWORD)throw new Error('Set TITAN_PASSWORD for the bench unit.');
const base=process.env.TITAN_URL||'http://127.0.0.1:18482';
const browser=await chromium.launch({headless:true}),page=await browser.newPage({viewport:{width:1440,height:1000},ignoreHTTPSErrors:process.env.TITAN_INSECURE_TLS==='1'}),errors=[],writes=[];
page.on('pageerror',e=>errors.push(e.stack));page.on('request',r=>{if(r.method()!=='GET')writes.push(r.method()+':'+new URL(r.url()).pathname);});
await page.route('**/*',route=>{
 const request=route.request(),path=new URL(request.url()).pathname;
 if(/\.(asp|cgi)(?:$|\/)/i.test(path)||request.resourceType()==='document'&&request.frame().parentFrame()){errors.push('Blocked legacy request: '+path);return route.abort();}
 const allowed=request.method()==='GET'||request.method()==='POST'&&path==='/api/v1/session'||process.env.TITAN_WRITE_TEST==='1'&&request.method()==='PUT'&&path==='/api/v1/settings/services';
 if(!allowed){errors.push('Blocked unexpected write: '+request.method()+' '+path);return route.abort();}
 return route.continue();
});
if(process.env.TITAN_LOCAL_BUILD==='1')await page.route('**/ui/**',async r=>{const p=new URL(r.request().url()).pathname;try{const body=await readFile(new URL('../dist-device/'+p.slice(4),import.meta.url));await r.fulfill({body,contentType:p.endsWith('.js')?'application/javascript':p.endsWith('.css')?'text/css':p.endsWith('.html')?'text/html':undefined});}catch{await r.continue();}});
await page.goto(base+'/ui/index.html');await expect(page.locator('#login-password')).toBeVisible();await page.locator('#login-password').fill(process.env.TITAN_PASSWORD);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.locator('h1')).toHaveText('Overview',{timeout:30000});const serial=await page.locator('[data-device=serial]').first().innerText();if(process.env.TITAN_SERIAL)assert.equal(serial,process.env.TITAN_SERIAL);
async function open(section,tab){await page.setViewportSize({width:1440,height:1000});await page.locator('.side-nav').getByText(section,{exact:true}).click();if(['Backup','Restart'].includes(tab))await page.getByRole('tab',{name:'Device',exact:true}).click();if(['CPI','CBSD status'].includes(tab))await page.getByRole('tab',{name:'SAS',exact:true}).click();if(tab)await page.getByRole('tab',{name:tab==='CPI'?'CPI installation':tab,exact:true}).click();await expect(page.locator('[data-settings-ready]')).toBeVisible({timeout:30000});await expect(page.locator('[data-settings-ready]')).toHaveAttribute('data-settings-tab',({ 'APN profiles':'apn','Band & selection':'selection','PCI lock':'lock','Cell scan':'scan','Operating mode':'mode','LAN & DHCP':'lan','Firewall':'firewall','Port forwards':'forwards','Routes':'routes','Device':'device','Access':'access','ACS':'services','SAS':'sas','CPI':'cpi','CBSD status':'sasStatus','Backup':'backup','Firmware':'firmware','Restart':'restart','Ping':'ping','Network status':'status'})[tab],{timeout:30000});}
const cases=[['Radio','APN profiles'],['Radio','Band & selection'],['Radio','PCI lock'],['Radio','Cell scan'],['Network','Operating mode'],['Network','LAN & DHCP'],['Network','Firewall'],['Network','Port forwards'],['Network','Routes'],['System','Device'],['System','Access'],['System','ACS'],['System','SAS'],['System','CPI'],['System','CBSD status'],['System','Backup'],['System','Firmware'],['System','Restart'],['Diagnostics','Ping'],['Diagnostics','Network status']];
for(const [section,tab]of cases.filter(([,tab])=>!process.env.TITAN_ONLY||process.env.TITAN_ONLY.split(',').includes(tab))){
 await open(section,tab);

 console.log(tab,await page.locator('[data-settings-ready] h2').allTextContents(),await page.locator('[data-control]').count(),'controls');
 await expect(page.locator('iframe')).toHaveCount(0);
 for(const width of [1440,390]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,tab+' overflow');}
 await page.setViewportSize({width:1440,height:1000});
 if(['ACS','SAS','APN profiles','Operating mode','Access'].includes(tab))await page.screenshot({path:'/tmp/titan-refinement-'+tab.replaceAll(' ','-')+'.png',fullPage:true});
}
if(process.env.TITAN_INTERACTION_TEST==='1'){
 await open('Radio','PCI lock');await page.getByRole('combobox',{name:'Cell selection',exact:true}).selectOption('2');
 await page.getByRole('button',{name:'Add entry',exact:true}).click();
 await expect(page.getByRole('spinbutton',{name:'PCI',exact:true}).first()).toBeVisible();
 assert.equal(await page.getByRole('textbox',{name:/EARFCN/i}).count(),0,'PCI lock must not ask for EARFCN');
 await page.getByRole('button',{name:/^(Discard|Reload)$/,exact:true}).click();
 await expect(page.getByRole('combobox',{name:'Cell selection',exact:true})).toHaveValue('0');
 await open('System','ACS');const interval=page.getByRole('spinbutton',{name:'Inform interval (seconds)',exact:true});const value=await interval.inputValue();
 await interval.fill('30');await page.getByRole('button',{name:'Save changes',exact:true}).click();assert.equal(await interval.evaluate(e=>e.validity.valid),false);
 await page.getByRole('button',{name:'Toggle color theme',exact:true}).click();await expect(interval).toHaveValue('30');
 const before=await page.locator('.page-head').boundingBox();await page.getByRole('tab',{name:'SAS',exact:true}).click();await expect(page.getByRole('dialog')).toBeVisible();await page.getByRole('button',{name:'Cancel',exact:true}).click();await expect(interval).toHaveValue('30');
 await page.getByRole('button',{name:/^(Discard|Reload)$/,exact:true}).click();await expect(interval).toHaveValue(value);
 await page.getByRole('tab',{name:'SAS',exact:true}).click();await expect(page.locator('[data-settings-ready]')).toHaveAttribute('data-settings-tab','sas');assert.deepEqual(await page.locator('.page-head').boundingBox(),before);
 await page.getByRole('button',{name:'Relinquish grant',exact:true}).click();await expect(page.getByRole('dialog')).toBeVisible();await page.getByRole('button',{name:'Cancel',exact:true}).click();
 await page.setViewportSize({width:390,height:844});await page.screenshot({path:'/tmp/titan-live-settings-phone.png',fullPage:true});
 console.log('PASS: PCI-only draft, discard, validation, theme retains edits, stable tabs and canceled SAS action');
}
assert.deepEqual(writes,['POST:/api/v1/session']);
if(process.env.TITAN_WRITE_TEST==='1'){
 assert.equal(serial,process.env.TITAN_SERIAL,'Explicit matching serial required for write test');
 await open('System','ACS');
 const input=page.getByRole('textbox',{name:'ACS URL',exact:true});await expect(input).toBeVisible();
 const interval=page.getByRole('spinbutton',{name:'Inform interval (seconds)',exact:true});
 const original=process.env.TITAN_RESTORE_INTERVAL||await interval.inputValue(),changed=original==='300'?'301':'300';
 const save=async value=>{await interval.fill(value);await page.getByRole('button',{name:'Save changes',exact:true}).click();await expect(page.locator('[data-native-host]')).toHaveAttribute('aria-busy','true');await expect(page.locator('[data-native-host]')).not.toHaveAttribute('aria-busy','true',{timeout:60000});await expect(page.locator('.device-error')).toBeHidden();await expect(page.locator('#toast')).toHaveText('Settings saved and read back from the Titan.');await expect(interval).toHaveValue(value);await page.getByRole('button',{name:/^(Discard|Reload)$/,exact:true}).click();await expect(interval).toHaveValue(value,{timeout:30000});};
 try{await save(changed);console.log('Real ACS write/readback confirmed');}finally{await open('System','ACS');await save(original);console.log('ACS interval restored:',original);}
}
console.log('Errors:',errors);assert.deepEqual(errors,[]);
await browser.close();
