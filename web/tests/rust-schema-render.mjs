// Render schemas produced by native Rust adapters without touching hardware.
// TITAN_SCHEMA_FILE=/tmp/titan-native-schemas.json node tests/rust-schema-render.mjs
import {chromium,expect} from '@playwright/test';
import {createServer} from 'vite';
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {parseSettings,SECTIONS} from '../src/device/settings-model.js';
import {sample} from './fixtures/telemetry.mjs';
if(!process.env.TITAN_SCHEMA_FILE)throw new Error('TITAN_SCHEMA_FILE must contain the native section-to-schema JSON map.');
const schemas=JSON.parse(await readFile(process.env.TITAN_SCHEMA_FILE,'utf8'));
for(const section of SECTIONS)parseSettings(schemas[section],section);
const server=await createServer({mode:'rust-device',server:{host:'127.0.0.1',port:4194,strictPort:true,watch:null,hmr:false}});
await server.listen();const browser=await chromium.launch({headless:true});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],forbidden=[];let sequence=0;
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',route=>{
  const request=route.request(),path=new URL(request.url()).pathname;
  if(/\.(asp|cgi)(?:$|\/)/i.test(path)||request.method()!=='GET'||request.resourceType()==='document'&&request.frame().parentFrame()){forbidden.push(request.method()+' '+path);return route.abort();}
  if(path==='/api/v1/session')return route.fulfill({json:{authenticated:true,csrf_token:'fixture-csrf'}});
  if(path==='/api/v1/telemetry')return route.fulfill({json:sample({sequence:++sequence})});
  if(path.startsWith('/api/v1/settings/'))return route.fulfill({json:schemas[path.split('/').at(-1)]});
  return route.continue();
 });
 const cases=[['Radio','APN profiles','apn'],['Radio','Band & selection','selection'],['Radio','PCI lock','lock'],['Radio','Cell scan','scan'],['Network','Operating mode','mode'],['Network','LAN & DHCP','lan'],['Network','Firewall','firewall'],['Network','Port forwards','forwards'],['Network','Routes','routes'],['System','Device','device'],['System','Access','access'],['System','SSH keys','ssh'],['System','ACS','services'],['System','SAS','sas'],['System','CPI','cpi'],['System','CBSD status','sasStatus'],['System','Backup','backup'],['System','Firmware','firmware'],['System','Restart','restart'],['Diagnostics','Ping','ping'],['Diagnostics','Network status','status']];
 await page.goto('http://127.0.0.1:4194/ui/');await expect(page.locator('h1')).toHaveText('Overview');
 for(const [section,tab,id]of cases){
  await page.setViewportSize({width:1440,height:1000});await page.locator('.side-nav').getByText(section,{exact:true}).click();
  if(['Backup','Restart'].includes(tab))await page.getByRole('tab',{name:'Device',exact:true}).click();
  if(['CPI','CBSD status'].includes(tab))await page.getByRole('tab',{name:'SAS',exact:true}).click();
  if(tab==='SSH keys')await page.getByRole('tab',{name:'Access',exact:true}).click();
  await page.getByRole('tab',{name:tab==='CPI'?'CPI installation':tab,exact:true}).click();
  await expect(page.locator('[data-settings-ready]')).toHaveAttribute('data-settings-tab',id);
  await expect(page.locator('iframe')).toHaveCount(0);
  for(const action of schemas[id].actions||[])await expect(page.locator(`[data-json-action="${action.id}"]`)).toHaveText(action.label);
  for(const width of [1440,390]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,id+' overflow at '+width);}
  console.log(id+': '+(await page.locator('[data-settings-ready] h2').allTextContents()).join(', '));
 }
 assert.deepEqual(errors,[]);assert.deepEqual(forbidden,[]);
 console.log('PASS: all 21 actual Rust schemas render on desktop/phone with no legacy requests, frames or writes.');
}finally{await browser.close();await server.close();}
