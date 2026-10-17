const previewBase=process.env.TITAN_PREVIEW_URL||'http://127.0.0.1:4180';
import {chromium,expect} from '@playwright/test';
import assert from 'node:assert/strict';
const browser=await chromium.launch();
const page=await browser.newPage({viewport:{width:1440,height:1000}});
const errors=[];page.on('pageerror',e=>errors.push(e.message));
// Functional tab actions wait for both selection and the preceding view
// transition. Otherwise a fast submit can act on the departing CPI form.
async function openTab(name){
 const settled=()=>page.waitForFunction(()=>!document.documentElement.hasAttribute('data-tab-transition')&&!document.documentElement.classList.contains('auth-transition'));
 await settled();const control=page.getByRole('tab',{name,exact:true});await control.click();
 await expect(control).toHaveAttribute('aria-selected','true');await settled();
}
await page.goto(previewBase+'/#radio');
await openTab('PCI lock');
await page.getByLabel('Connection method').selectOption('Preferred list');
assert.equal(await page.getByRole('spinbutton',{name:/EARFCN/}).count(),0);
await page.getByLabel('PCI 1',{exact:true}).fill('0');
await page.getByLabel('Lock to preferred cells').check();
await page.getByRole('button',{name:'Add cell',exact:true}).click();
await page.getByLabel('PCI 2',{exact:true}).fill('0');
await page.getByRole('button',{name:'Apply cell selection',exact:true}).click();
await page.getByRole('status').filter({hasText:'Remove duplicate PCI entries.'}).waitFor();
await page.getByLabel('PCI 2',{exact:true}).fill('503');
await page.getByRole('button',{name:'Apply cell selection',exact:true}).click();
await page.getByRole('dialog').getByRole('button',{name:'Apply cell selection',exact:true}).click();
assert.equal(await page.getByLabel('Lock to preferred cells').isChecked(),true);
await page.reload();await openTab('PCI lock');
assert.equal(await page.getByLabel('PCI 1',{exact:true}).inputValue(),'0');
assert.equal(await page.getByLabel('PCI 2',{exact:true}).inputValue(),'503');
await page.goto(previewBase+'/#align');
await page.getByText('Cell selection: Preferred list / PCI 0, 503',{exact:true}).waitFor();
await page.getByRole('button',{name:'Edit PCI lock'}).click();
await page.getByLabel('Connection method').selectOption('Automatic');
await page.getByRole('button',{name:'Apply cell selection',exact:true}).click();
await page.getByRole('dialog').getByRole('button',{name:'Apply cell selection',exact:true}).click();
await page.goto(previewBase+'/#system');
await openTab('SAS');
await page.getByLabel('User ID',{exact:true}).fill('qa-demo-user');
await page.getByLabel('SAS URL',{exact:true}).fill('https://qa.example.com/sas');
await page.getByLabel('Maximum EIRP (dBm/MHz)',{exact:true}).fill('0');
await page.getByRole('button',{name:'Save SAS settings'}).click();
await openTab('Antenna & GPS');
await page.getByLabel('GPS latitude (°)',{exact:true}).fill('-33.50');
await page.getByLabel('GPS longitude (°)',{exact:true}).fill('-87.15');
await page.getByLabel('Antenna azimuth (°)',{exact:true}).fill('0');
await page.getByRole('button',{name:'Save installation',exact:true}).click();
assert.equal(await page.getByLabel('GPS latitude (°)',{exact:true}).inputValue(),'-33.50');
await openTab('CPI');
await page.getByLabel('Antenna downtilt (°)',{exact:true}).fill('-3');
await page.getByLabel('Height type',{exact:true}).selectOption('AMSL');
await page.getByLabel('Key encryption password',{exact:true}).fill('do-not-store-this');
await page.getByRole('button',{name:'Save CPI data'}).click();
assert.equal((await page.evaluate(()=>localStorage.getItem('titan-demo-config'))).includes('do-not-store-this'),false);
await page.getByLabel('Calculation method').selectOption('Encrypted data');
await page.getByRole('button',{name:'Switch format'}).click();
await page.getByLabel('Protected header',{exact:true}).fill('DEMO HEADER');
await page.getByLabel('Encoded CPI signed data',{exact:true}).fill('DEMO DATA');
await page.getByLabel('Digital signature',{exact:true}).fill('DEMO SIGNATURE');
await page.getByRole('button',{name:'Save CPI data'}).click();
assert.equal((await page.evaluate(()=>localStorage.getItem('titan-demo-config'))).includes('DEMO SIGNATURE'),false);
await openTab('Certificates & CRL');
await page.getByLabel('Certificate file (.p12)',{exact:true}).setInputFiles({name:'sample.p12',mimeType:'application/octet-stream',buffer:Buffer.from('DUMMY FILE')});
await page.getByLabel('Encryption password',{exact:true}).fill('dummy-password');
await page.getByRole('button',{name:'Simulate certificate load'}).click();
await page.getByRole('cell',{name:'sample.p12',exact:true}).waitFor();
assert.equal((await page.evaluate(()=>localStorage.getItem('titan-demo-config'))).includes('dummy-password'),false);
await openTab('Registration');
await page.getByRole('button',{name:'Deregister',exact:true}).click();
await page.getByRole('button',{name:'Deregister demo',exact:true}).click();
await page.getByText('Unregistered',{exact:true}).waitFor();
await page.goto(previewBase+'/#overview');
assert.equal(await page.locator('[data-health=sas]').innerText(),'No grant');
await page.goto(previewBase+'/#system');await openTab('SAS');
await page.getByRole('button',{name:'Simulate registration',exact:true}).click();
await page.getByRole('dialog').getByRole('button',{name:'Simulate registration',exact:true}).click();
await page.getByText('Registered',{exact:true}).waitFor();
// Visual layout QA for the added forms, both themes and narrow phones.
for(const width of [1440,390,320])for(const dark of [false,true]){
 await page.setViewportSize({width,height:900});
 await page.evaluate(d=>document.documentElement.classList.toggle('dark',d),dark);
 await page.goto(previewBase+'/#system');await openTab('SAS');
 for(const tab of ['Registration','Antenna & GPS','CPI','Certificates & CRL']){
  await openTab(tab);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`${width} ${dark} ${tab} overflow`);
  assert.equal(await page.locator('.dot').count(),0);
  assert.equal(await page.evaluate(()=>[...document.querySelectorAll('.card,.btn,input,select,textarea,.pill')].some(e=>parseFloat(getComputedStyle(e).borderTopLeftRadius)!==0)),false,'Rounded corners');
  await page.evaluate(()=>document.fonts.ready);
  if(width!==320)await page.screenshot({path:`test-results/refined-sas-${tab.replaceAll(/[^a-zA-Z]/g,'').toLowerCase()}-${width}-${dark?'dark':'light'}.png`,fullPage:true});
 }
}
assert.deepEqual(errors,[]);
console.log('PASS: PCI-only lock (0–503), duplicates, persistence, unlock; SAS fields, negative coordinates, CPI forms, secret-free saves, certificate simulation, registration/grant state, all added forms at 1440/390/320 in both themes, square corners, no dots.');
await browser.close();
