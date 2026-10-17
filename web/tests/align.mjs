// Align screen in the demo build (spec 6.2): layouts, reading-counted marks,
// honest big number, cell change archive, steps, export, motion, sound, keys.
const previewBase=process.env.TITAN_PREVIEW_URL||'http://127.0.0.1:4180';
import {chromium,expect} from '@playwright/test';
import assert from 'node:assert/strict';
import {mkdir,readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
const output=fileURLToPath(new URL('../test-results/',import.meta.url));
await mkdir(output,{recursive:true});
const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1440,height:1000},acceptDownloads:true});
const errors=[];
page.on('pageerror',e=>errors.push(e.message));
page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
const controls=async fn=>{await page.getByRole('button',{name:'Demo controls',exact:true}).last().click();await fn();await page.getByRole('button',{name:'Close demo controls'}).click();};
const label=page.locator('[data-action=mark] [data-mark-label]');

// 1-2. Layouts render cleanly with a single Mark button and Quality reading.
for(const [name,width,height] of [['desktop',1440,1000],['phone',390,844],['small',320,700],['landscape',844,390]]){
 await page.setViewportSize({width,height});
 await page.goto(previewBase+'/#align');
 await expect(page.locator('h1')).toHaveText('Antenna alignment');
 await expect(page.locator('[data-live=sinr]')).not.toHaveText('—',{timeout:5000});
 assert.equal(await page.locator('[data-action=mark]').count(),1,name+' mark buttons');
 assert.equal(await page.locator('[data-live=sinr]').count(),1,name+' quality readings');
 assert.equal(await page.locator('[data-live=pci]').count(),1,name+' cell readings');
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,name+' overflow');
 if(name!=='desktop'){
  const box=await page.locator('[data-action=mark]').boundingBox();
  assert.ok(box&&box.y>=0&&box.y+box.height<=height,name+': Mark is reachable without scrolling');
  // The instruction is never hidden under the sticky action bar.
  const hint=await page.locator('[data-hint] strong').boundingBox(),bar=await page.locator('.align-actions').boundingBox();
  assert.ok(hint&&bar&&hint.y>=0&&(hint.y+hint.height<=bar.y+0.5||hint.x>=bar.x+bar.width-0.5),name+': guidance sits above the action bar');
  const next=await page.locator('[data-align-action=next]').boundingBox();
  assert.ok(next&&next.y+next.height<=height,name+': the action row is on screen');
 }
 await page.screenshot({path:`${output}align-${name}.png`,fullPage:name!=='landscape'});
}
await page.setViewportSize({width:390,height:844});
await page.getByRole('button',{name:'Toggle color theme'}).click();
await page.screenshot({path:output+'align-phone-dark.png',fullPage:true});
await page.getByRole('button',{name:'Toggle color theme'}).click();

// 3, 9. Keyboard mark counts readings; undo removes it.
await page.setViewportSize({width:1440,height:1000});
await page.goto(previewBase+'/#align');
await expect(page.locator('[data-live=sinr]')).not.toHaveText('—',{timeout:5000});
await page.locator('h1').click();
await page.keyboard.press('m');
await expect(label).toHaveText(/Hold still · reading [0-3] of 3/);
await expect(page.locator('[data-action=mark]')).toBeDisabled();
await expect(page.locator('.position')).toHaveCount(1,{timeout:8000});
await page.keyboard.press('u');
await expect(page.locator('.position')).toHaveCount(0);

// 8. Sound turns on inside the click.
await expect(page.locator('[data-action=audio]')).toHaveText('Sound off');
await page.locator('[data-action=audio]').click();
await expect(page.locator('[data-action=audio]')).toHaveText('Sound on');
await page.locator('[data-action=audio]').click();
await expect(page.locator('[data-action=audio]')).toHaveText('Sound off');

// 5. A cell change archives positions instead of mixing sectors.
for(const n of [1,2]){
 await page.getByRole('button',{name:'Mark this position',exact:true}).click();
 await expect(page.locator('.position')).toHaveCount(n,{timeout:8000});
}
await controls(()=>page.getByLabel('Connection scenario').selectOption('changed'));
await expect(page.locator('.position')).toHaveCount(0);
await expect(page.locator('.position-prev')).toHaveCount(2);
await expect(page.locator('[data-align-banner]')).toContainText('Now on PCI 142');
await expect(page.locator('[data-live=pci]')).toHaveText('142');
await controls(()=>page.getByLabel('Connection scenario').selectOption('connected'));

// 6. Steps switch the screen; Record shows acceptance and exports CSV.
for(const step of ['peak','confirm','record','find']){
 await page.locator(`[data-align-steps] [data-step=${step}]`).click();
 await expect(page.locator('[data-align]')).toHaveAttribute('data-step',step);
}
await page.getByRole('button',{name:'Mark this position',exact:true}).click();
await expect(page.locator('.position')).toHaveCount(1,{timeout:8000});
await page.locator('[data-align-steps] [data-step=record]').click();
await expect(page.locator('[data-align-record]')).toBeVisible();
await expect(page.locator('[data-align-record] table').first()).toBeVisible();
const downloadEvent=page.waitForEvent('download');
await page.getByRole('button',{name:'Export',exact:true}).click();
const download=await downloadEvent;
assert.equal(download.suggestedFilename(),'titan-demo-alignment.csv');
assert.match(await readFile(await download.path(),'utf8'),/^position,pci,sinr_db,rsrp_dbm,source,/);
await page.locator('[data-align-steps] [data-step=find]').click();

// 4. Slow modem: honest waiting copy, and the big number moves once per reading.
await controls(()=>page.getByLabel('Align scenario').selectOption('slow'));
await expect(page.locator('[data-align-fresh]')).toContainText(/next in about|Waiting for the modem|Reading \d+ s old|just now/,{timeout:10000});
// No tween or interpolation: every value shown is a modem sample, and samples
// are at least 400 ms apart even inside a burst, so no value flashes by.
const runs=await page.evaluate(()=>new Promise(resolve=>{const el=document.querySelector('[data-align-big]'),runs=[],t0=performance.now();let last=el.textContent,at=t0;
 const step=now=>{const v=el.textContent;if(v!==last){runs.push([last,Math.round(now-at)]);last=v;at=now;}if(now-t0<9000)requestAnimationFrame(step);else resolve(runs);};requestAnimationFrame(step);}));
assert.ok(runs.length>=1,"No reading arrived in 9 s of the slow modem");
for(const [value,ms] of runs.slice(1))assert.ok(ms>=300,`Big number showed ${value} for only ${ms} ms`);
await controls(()=>page.getByLabel('Align scenario').selectOption('normal'));

// 7. Reduced motion stops the meter tween.
await page.emulateMedia({reducedMotion:'reduce'});
assert.equal(await page.locator('[data-gauge=sinr] .gauge-value').evaluate(el=>getComputedStyle(el).transitionDuration),'0s');
await page.emulateMedia({reducedMotion:'no-preference'});

assert.deepEqual(errors,[],'Browser errors');
await browser.close();
console.log('PASS: Align desktop/phone/landscape/dark; one Mark and Quality; reading-counted capture; keyboard mark/undo; sound toggle; cell change archive; steps, record and CSV export; slow modem honesty; reduced motion.');
