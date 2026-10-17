import assert from 'node:assert/strict';
import {test} from 'node:test';
import {parseJsonTelemetry,SampleClock,jsonRequest,session,logout} from '../src/device/json-client.js';
import {SessionExpired} from '../src/device/errors.js';
import {sample} from './fixtures/telemetry.mjs';

test('JSON contract accepts measured values and explicit unavailable measurements',()=>{
 assert.equal(parseJsonTelemetry(sample()).telemetry.sinr,18.6);
 const unavailable=sample();for(const k of ['sinr','rsrp','rsrq','pci','ethernet'])unavailable.telemetry[k]=null;
 unavailable.telemetry.chains=[null,null];unavailable.telemetry.attached=false;
 assert.equal(parseJsonTelemetry(unavailable),unavailable);
});
test('malformed source timing and numeric strings cannot masquerade as a sample',()=>{
 for(const invalid of [sample({sequence:-1}),sample({sequence:1.1}),sample({age_ms:-1}),sample({stale:undefined}),sample({telemetry:{...sample().telemetry,sinr:'18.6'}}),sample({telemetry:{...sample().telemetry,chains:[Infinity]}})])assert.throws(()=>parseJsonTelemetry(invalid),/incomplete telemetry/);
});
test('repeated cache reads do not rejuvenate source age or advance capture',()=>{
 const clock=new SampleClock();assert.equal(clock.accept(sample(),10000),true);
 assert.equal(clock.accept(sample(),16000),false);assert.equal(clock.sampledAt,10000);
 assert.equal(clock.fresh(17999),true);assert.equal(clock.fresh(18000),false);
 assert.equal(clock.accept(sample({sequence:2}),19000),true);assert.equal(clock.fresh(19000),true);
});
test('server age, transport delay and explicit stale state gate telemetry',()=>{
 const clock=new SampleClock();clock.accept(sample({age_ms:7500}),10000,600);
 assert.equal(clock.fresh(10000),false);
 clock.accept(sample({sequence:2,stale:true}),11000);assert.equal(clock.fresh(11000),false);
 clock.accept(sample({sequence:3}),12000);assert.equal(clock.fresh(12000),true);
});
test('session token remains in memory, logout uses CSRF, 401 expires and HTML is rejected',async()=>{
 const original=globalThis.fetch;const requests=[];
 try{
  globalThis.fetch=async(path,options)=>{requests.push({path,options});return new Response(JSON.stringify({authenticated:true,csrf_token:'fixture-csrf'}),{headers:{'Content-Type':'application/json'}});};
  await session('fixture-password');assert.deepEqual(JSON.parse(requests[0].options.body),{password:'fixture-password'});
  globalThis.fetch=async(path,options)=>{requests.push({path,options});return new Response(null,{status:204});};
  await logout();assert.equal(requests.at(-1).options.headers['X-CSRF-Token'],'fixture-csrf');
  globalThis.fetch=async()=>new Response('{}',{status:401,headers:{'Content-Type':'application/json'}});
  await assert.rejects(jsonRequest('/api/v1/telemetry'),SessionExpired);
  globalThis.fetch=async()=>new Response('<html>Sign in</html>',{headers:{'Content-Type':'text/html'}});
  await assert.rejects(jsonRequest('/api/v1/telemetry'),/invalid API response/);
 }finally{globalThis.fetch=original;}
});
