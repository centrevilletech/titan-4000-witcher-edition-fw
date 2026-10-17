import test from 'node:test';
import assert from 'node:assert/strict';
import {probeFirmwareReturn} from '../src/device/firmware-reconnect.js';
test('old live UI is not mistaken for a completed reboot',async()=>{
 const health=id=>async()=>({ok:true,json:async()=>({service:'titan-api',boot_id:id})});
 assert.equal(await probeFirmwareReturn('before',health('before')),null);
 assert.equal(await probeFirmwareReturn('before',health('after')),'witcher');
 assert.equal(await probeFirmwareReturn(null,health('after')),null);
});
test('stock return is recognized without a Witcher API or session',async()=>{
 const calls=[];const fetcher=async(path,opts)=>{calls.push(path);assert.equal(opts.credentials,'omit');assert.equal(opts.cache,'no-store');if(path.includes('/api/'))throw new Error('connection closed');return {ok:true,text:async()=>'<html><frameset><frame src="../Status.asp"></frameset></html>'};};
 assert.equal(await probeFirmwareReturn('before',fetcher),'stock');assert.deepEqual(calls,['/api/v1/health','/']);
});
test('outage and unrelated HTML never confirm success or repeat a write',async()=>{
 assert.equal(await probeFirmwareReturn('before',async()=>{throw new Error('offline');}),null);
 assert.equal(await probeFirmwareReturn('before',async()=>({ok:true,json:async()=>({}),text:async()=>'<h1>Proxy error</h1>'})),null);
});

test('version probes ignore outages and HTML without a firmware identity',async()=>{
 const {readServedVersion}=await import('../src/device/firmware-reconnect.js');
 assert.equal(await readServedVersion(async()=>{throw Error('offline');}),null);
 assert.equal(await readServedVersion(async()=>({ok:true,text:async()=>'<h1>Login</h1>'})),null);
 assert.equal(await readServedVersion(async(path,options)=>{assert.equal(path,'/ui/index.html');assert.equal(options.cache,'no-store');return {ok:true,text:async()=>'<meta name="witcher-version" content="1.0.0-rc.7" />'};}),'1.0.0-rc.7');
});
test('return notices only describe the version actually loaded and expire',async()=>{
 const {rememberFirmwareReturn,firmwareReturnNotice}=await import('../src/device/firmware-reconnect.js');
 const values=new Map(),storage={getItem:k=>values.get(k),setItem:(k,v)=>values.set(k,v)};
 rememberFirmwareReturn('1.0.0-rc.7','restarted',storage);
 assert.equal(firmwareReturnNotice('1.0.0-rc.6',storage),'');
 assert.match(firmwareReturnNotice('1.0.0-rc.7',storage),/Device restarted. Now running Witcher v1.0.0-rc.7/);
 for(const [key,value]of values){const entry=JSON.parse(value);entry.at-=600001;values.set(key,JSON.stringify(entry));}
 assert.equal(firmwareReturnNotice('1.0.0-rc.7',storage),'');
});
