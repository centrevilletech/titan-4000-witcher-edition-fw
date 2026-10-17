const previewBase=process.env.TITAN_PREVIEW_URL||'http://127.0.0.1:4180';
import { chromium, expect } from '@playwright/test';
import assert from 'node:assert/strict';
import { readFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
const output=fileURLToPath(new URL('../test-results/',import.meta.url));
const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1440,height:1000}});
const errors=[];
page.on('pageerror',e=>errors.push(e.message));
// Exercise timing-sensitive helpers independently of the telemetry timer.
await page.route('**/motion-harness.html',r=>r.fulfill({contentType:'text/html',body:'<span id="reading"></span><dialog id="modal"></dialog>'}));
const source=await readFile(new URL('../src/motion.js',import.meta.url),'utf8');
await page.route('**/motion-test.js',r=>r.fulfill({contentType:'text/javascript',body:source}));
await page.goto(previewBase+'/motion-harness.html');
await page.evaluate(async()=>{window.motion=await import('/motion-test.js');});
assert.deepEqual(await page.evaluate(()=>{
 const el=document.querySelector('#reading');
 motion.setLiveText(el,'18.6');const initial=el.getAnimations().length;
 motion.setLiveText(el,'18.7');const changed=el.getAnimations().length;
 const animation=el.getAnimations()[0];
 motion.setLiveText(el,'18.7');
 return {initial,changed,same:el.getAnimations()[0]===animation,value:el.textContent};
}),{initial:0,changed:1,same:true,value:'18.7'});
await page.evaluate(()=>{
 const modal=document.querySelector('#modal');
 motion.showDialog(modal,'First');motion.closeDialog(modal);motion.showDialog(modal,'Replacement');
});
await page.waitForTimeout(400);
assert.equal(await page.locator('dialog').isVisible(),true,'Replacement survives pending close');
await page.evaluate(()=>motion.closeDialog(document.querySelector('dialog')));
await expect(page.locator('dialog')).not.toBeVisible();
await page.emulateMedia({reducedMotion:'reduce'});
assert.deepEqual(await page.evaluate(()=>{
 const el=document.querySelector('#reading');motion.setLiveText(el,'19.2');
 let rendered=false;motion.transitionContent(()=>rendered=true);
 return {animations:el.getAnimations().length,rendered,value:el.textContent};
}),{animations:0,rendered:true,value:'19.2'});
await page.emulateMedia({reducedMotion:'no-preference'});
assert.equal(await page.evaluate(()=>{
 document.startViewTransition=undefined;let rendered=false;
 motion.transitionContent(()=>rendered=true);return rendered;
}),true,'Browsers without View Transitions render immediately');
// Validate the composed UI, rapid navigation, keyboard dismissal and layout.
await page.goto(previewBase+'/#overview');
await page.evaluate(async()=>{
 for(const route of ['align','system','network','radio','align']){
  location.hash=route;await new Promise(resolve=>setTimeout(resolve,25));
 }
});
await expect(page.locator('h1')).toHaveText('Antenna alignment');
await page.waitForTimeout(700);
assert.equal(await page.locator('[data-hint]').evaluate(el=>!!el.closest('.card')),true);
assert.equal(await page.locator('[data-hint]').evaluate(el=>getComputedStyle(el).backgroundColor),'rgba(0, 0, 0, 0)');
const details=page.locator('[data-align-details]');
if(!await details.evaluate(el=>el.open))await details.locator('summary').click();
await expect(details.locator('dl')).toBeVisible();
await mkdir(output,{recursive:true});
await page.screenshot({path:output+'refined-guidance-desktop.png',fullPage:true});
for(const dark of [false,true])for(const width of [390,320]){
 await page.setViewportSize({width,height:844});
 await page.evaluate(dark=>document.documentElement.classList.toggle('dark',dark),dark);
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.screenshot({path:`${output}refined-guidance-${width}-${dark?'dark':'light'}.png`,fullPage:true});
}
await page.setViewportSize({width:1440,height:1000});
await page.goto(previewBase+'/#radio');
await page.getByRole('tab',{name:'Cell scan'}).click();
await page.getByRole('button',{name:'Scan cells',exact:true}).click();
await page.waitForTimeout(300);
const bounds=await page.locator('dialog').boundingBox();
assert.ok(Math.abs(bounds.x+bounds.width/2-720)<2&&Math.abs(bounds.y+bounds.height/2-500)<2,'Animated dialog stays centered');
await page.keyboard.press('Escape');
await expect(page.locator('dialog')).not.toBeVisible();
await page.goto(previewBase+'/#network');
await expect(page.locator('h1')).toHaveText('Network');
await page.waitForTimeout(500);
await page.evaluate(()=>{window.headingRef=document.querySelector('.page-head');window.tabsRef=document.querySelector('[data-tablist=network]');window.headingBounds=headingRef.getBoundingClientRect().toJSON();});
for(const tab of ['LAN & DHCP','Firewall','Routes','Operating mode']){
 await page.getByRole('tab',{name:tab,exact:true}).click();
 await expect(page.getByRole('tab',{name:tab,exact:true})).toHaveAttribute('aria-selected','true');
 assert.deepEqual(await page.evaluate(()=>({sameHeading:headingRef===document.querySelector('.page-head'),sameTabs:tabsRef===document.querySelector('[data-tablist=network]'),x:headingRef.getBoundingClientRect().x-headingBounds.x,y:headingRef.getBoundingClientRect().y-headingBounds.y,animations:headingRef.getAnimations().length})),{sameHeading:true,sameTabs:true,x:0,y:0,animations:0},'Tab changes preserve stationary page heading and tab labels');
}
await page.emulateMedia({reducedMotion:'reduce'});
await page.goto(previewBase+'/#align');
assert.equal(await page.evaluate(()=>document.getAnimations().length),0,'Reduced-motion UI has no running animations');
assert.deepEqual(errors,[]);
await browser.close();
console.log('PASS: changed readings fade; unchanged readings stay still; rapid navigation; replacement dialogs; keyboard dismissal; centered dialogs; reduced motion; fallback; inline guidance at desktop/390/320 in both themes.');
