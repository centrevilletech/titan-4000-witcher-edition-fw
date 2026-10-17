import {chromium, expect} from '@playwright/test';
import {createServer} from 'node:http';
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
const version=readFileSync(new URL('../../VERSION',import.meta.url),'utf8').trim();
const template=readFileSync(new URL('../../userspace/firstboot/src/setup.html',import.meta.url),'utf8');
let mode='setup',requests=[],healthy=false,stalled=false;
const server=createServer(async(req,res)=>{
 let body='';for await(const chunk of req)body+=chunk;
 if(req.url==='/configure'){
  const input=JSON.parse(body);requests.push(input);
  assert.equal(req.headers['x-witcher-setup'],'1');
  assert.equal(req.headers.origin,base);
  res.setHeader('Content-Type','application/json');
  if(input.password!=='fixture-password'){res.statusCode=401;res.end(JSON.stringify({message:'Use the existing device administrator password.'}));return;}
  healthy=true;res.end(JSON.stringify({message:'Setup saved. Starting Witcher.'}));return;
 }
 if(req.url==='/api/v1/health'){if(stalled)return;res.setHeader('Content-Type','application/json');res.statusCode=healthy?200:503;res.end(JSON.stringify({service:'titan-api'}));return;}
 if(req.url==='/api/v1/session'){assert.equal(JSON.parse(body).password,'fixture-password');res.end('{}');return;}
 res.setHeader('Content-Type','text/html');
 res.end(req.url==='/ui/'?'<h1>Witcher panel</h1>':template.replaceAll('{{VERSION}}',version).replaceAll('{{MODE}}',mode));
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const base=`http://127.0.0.1:${server.address().port}`;
const browser=await chromium.launch({headless:true});
try{
 const page=await browser.newPage();await page.goto(base);
 await expect(page.locator('h1')).toHaveText(`Witcher v${version}`);
 await page.getByLabel('Device administrator password').fill('wrong-password');
 await page.getByRole('button',{name:'Finish setup'}).click();
 await expect(page.getByRole('status')).toContainText('existing device administrator password');
 await page.getByLabel('Device administrator password').fill('fixture-password');
 await page.getByRole('button',{name:'Finish setup'}).click();
 await expect(page.locator('h1')).toHaveText('Witcher panel',{timeout:10000});
 assert.match(requests[1].seed,/^[0-9a-f]{128}$/);assert.notEqual(requests[0].seed,requests[1].seed);
 assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
 mode='recovery';requests=[];await page.goto(base);
 await page.getByLabel('Device administrator password').fill('fixture-password');
 await page.getByRole('button',{name:'Open factory desktop recovery'}).click();
 await expect.poll(()=>requests.length).toBe(1);assert.equal(requests[0].action,'vendor');assert.equal(requests[0].seed,undefined);
 await expect(page.getByRole('button',{name:'Retry Witcher'})).toBeEnabled();
 await page.getByLabel('Device administrator password').fill('fixture-password');
 await page.getByRole('button',{name:'Retry Witcher'}).click();
 await expect.poll(()=>requests.length).toBe(2);assert.equal(requests[1].action,'native');
 mode='setup';stalled=true;await page.goto(base);
 await page.clock.install();
 await page.getByLabel('Device administrator password').fill('fixture-password');
 await page.getByRole('button',{name:'Finish setup'}).click();
 await expect(page.getByRole('status')).toContainText('Setup saved');
 await page.clock.runFor(182000);
 await expect(page.getByRole('status')).toContainText('panel has not answered');
 await expect(page.getByRole('button',{name:'Finish setup'})).toBeEnabled();
 console.log('PASS: first-boot password rejection, fresh browser seed, automatic panel sign-in, no stored credentials, factory/native recovery, and a bounded wait when health never answers.');
}finally{await browser.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
