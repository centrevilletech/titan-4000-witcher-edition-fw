// Live Rust login/reload/logout qualification; no configuration writes.
import {chromium,expect} from '@playwright/test';
import assert from 'node:assert/strict';
const base=process.env.TITAN_URL||'http://127.0.0.1:18482';
if(!process.env.TITAN_PASSWORD)throw new Error('Set TITAN_PASSWORD for the bench unit.');
const browser=await chromium.launch({headless:true});
try{
 const context=await browser.newContext({viewport:{width:1440,height:1000},ignoreHTTPSErrors:process.env.TITAN_INSECURE_TLS==='1'}),page=await context.newPage(),errors=[],writes=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',route=>{
  const request=route.request(),path=new URL(request.url()).pathname;
  if(/\.(asp|cgi)(?:$|\/)/i.test(path)||request.resourceType()==='document'&&request.frame().parentFrame()){errors.push('Blocked legacy request '+path);return route.abort();}
  if(request.method()!=='GET'){
   if(path!=='/api/v1/session'||!['POST','DELETE'].includes(request.method())){errors.push('Blocked unexpected write '+path);return route.abort();}
   writes.push(request.method()+':'+path);
  }
  return route.continue();
 });
 await page.goto(base+'/');await expect(page.locator('#login-password')).toBeVisible({timeout:15000});
 await page.locator('#login-password').fill(process.env.TITAN_PASSWORD);
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.locator('h1')).toHaveText('Overview',{timeout:45000});
 const serial=await page.locator('[data-device=serial]').first().innerText();
 if(process.env.TITAN_SERIAL)assert.equal(serial,process.env.TITAN_SERIAL);
 await expect(page.locator('[data-live=sinr]').first()).not.toHaveText('—');
 // Each scheme has its own cookie: a Secure one would block a plain one of the same name.
 const https=new URL(base).protocol==='https:',cookie=(await context.cookies(base)).find(c=>c.name===(https?'__Host-titan_session':'titan_http_session'));
 assert.ok(cookie,'Authenticated session cookie must exist');assert.equal(cookie.httpOnly,true);assert.equal(cookie.sameSite,'Strict');
 assert.equal(cookie.secure,https,'Only HTTPS login issues a Secure cookie');
 const session=await context.request.get(base+'/api/v1/session');assert.equal(session.status(),200);assert.equal((await session.json()).authenticated,true);
 await page.goto(base+'/#align');
 await expect(page.locator('h1')).toHaveText('Antenna alignment',{timeout:15000});
 await expect(page.locator('[data-live=sinr]').first()).not.toHaveText('—');
 await page.getByRole('button',{name:'Mark this position',exact:true}).last().click();
 await expect(page.locator('.position')).toHaveCount(1,{timeout:40000});
 if(process.env.TITAN_SCREENSHOT){await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:process.env.TITAN_SCREENSHOT,fullPage:true});}
 await page.getByRole('button',{name:'Sign out',exact:true}).click();
 await expect(page.locator('#login-password')).toBeVisible({timeout:10000});
 assert.equal((await context.request.get(base+'/api/v1/telemetry')).status(),401);
 assert.equal((await context.request.get(base+'/api/v1/session')).status(),401);
 assert.deepEqual(errors,[]);assert.deepEqual(writes,['POST:/api/v1/session','DELETE:/api/v1/session']);
 console.log(`PASS: ${serial}, Rust login, HttpOnly/Strict${new URL(base).protocol==='https:'?'/Secure':''} session, authenticated direct Align entry, real position, logout and protected API401; no JS errors.`);
}finally{await browser.close();}
