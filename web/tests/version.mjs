// Exercise the built device bundle, including login before telemetry is available.
import {chromium,expect} from '@playwright/test';
import {preview} from 'vite';
import {readFileSync} from 'node:fs';
import {sample} from './fixtures/telemetry.mjs';
const version=readFileSync(new URL('../../VERSION',import.meta.url),'utf8').trim();
const label=`Witcher v${version}`;
const server=await preview({mode:'rust-device',preview:{host:'127.0.0.1',port:4196,strictPort:true}});
const browser=await chromium.launch({headless:true});
try{
 for(const viewport of [{width:1440,height:1000},{width:390,height:844}]){
  const page=await browser.newPage({viewport});let authenticated=false,sequence=0;
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.route('**/ui/device-mac.txt',route=>route.fulfill({contentType:'text/plain',body:'02:00:5e:40:00:01\n'}));
  await page.route('**/api/v1/session',async route=>{
   if(route.request().method()==='POST')authenticated=true;
   if(route.request().method()==='DELETE')authenticated=false;
   await route.fulfill({status:authenticated?200:401,json:authenticated?{authenticated:true,csrf_token:'fixture-token'}:{error:'unauthorized'}});
  });
  await page.route('**/api/v1/telemetry',route=>route.fulfill({status:authenticated?200:401,json:authenticated?sample({sequence:++sequence}):{error:'unauthorized'}}));
  await page.goto('http://127.0.0.1:4196/ui/#login');
  await expect(page.locator('.login-version')).toHaveText(label);
  await expect(page.locator('.login-version')).toBeVisible();
  await expect(page.locator('[data-login-mac]')).toHaveText('02:00:5E:40:00:01');
  await expect(page.locator('[data-login-mac]')).toBeVisible();
  const identity=await page.locator('.login-identity').boundingBox();
  const caption=await page.locator('.login-caption').boundingBox();
  expect(identity.y).toBeGreaterThanOrEqual(caption.y+caption.height);
  await page.locator('#login-password').fill('fixture-password');
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await expect(page.locator('h1')).toHaveText('Overview');
  await expect(page.locator('.edition')).toHaveText(label);
  await expect(page.locator('.footer')).toContainText(`${label} / Base V1.6.0.P0.4172`);
  await page.getByRole('button',{name:'Sign out',exact:true}).click();
  await expect(page.locator('[data-login-mac]')).toHaveText('02:00:5E:40:00:01');
  await page.route('**/ui/device-mac.txt',route=>route.fulfill({status:404}));
  await page.reload();
  await expect(page.locator('[data-login-mac]')).toHaveText('Unavailable');
  await expect(page.getByRole('button',{name:'Sign in',exact:true})).toBeEnabled();
  await expect.poll(()=>errors).toEqual([]);
  await page.close();
 }
 console.log(`PASS: ${label} and unit MAC before login on desktop/mobile, logout, unavailable MAC without blocking login; base firmware remains separate.`);
}finally{await browser.close();await new Promise(resolve=>server.httpServer.close(resolve));}
