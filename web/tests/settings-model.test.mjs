import {test} from 'node:test';
import assert from 'node:assert/strict';
import {parseSettings,serializeSettings,readbackMatches,pathKey,SECTIONS} from '../src/device/settings-model.js';
import {settingsFixtures} from './fixtures/settings.mjs';

test('every explicit section schema satisfies the UI contract',()=>{
 const fixtures=settingsFixtures();assert.deepEqual(Object.keys(fixtures),SECTIONS);
 for(const [section,model]of Object.entries(fixtures))assert.equal(parseSettings(model,section).section,section);
});
test('secrets are dropped at the read boundary and omitted until edited',()=>{
 const source=settingsFixtures().services;source.values.password='must-never-render';
 const model=parseSettings(source,'services');assert.equal(model.values.password,undefined);
 const draft=structuredClone(model.values);let values=serializeSettings(model,draft);
 assert.equal(Object.hasOwn(values,'password'),false);assert.equal(Object.hasOwn(values,'stun_server'),false);
 draft.password='replacement';values=serializeSettings(model,draft,new Set([pathKey(['password'])]));assert.equal(values.password,'replacement');
});
test('nested list identity survives saves while untouched row passwords do not',()=>{
 const model=parseSettings(settingsFixtures().apn,'apn'),draft=structuredClone(model.values);
 draft.profiles[1].password='replacement';const values=serializeSettings(model,draft,new Set([pathKey(['profiles',1,'password'])]));
 assert.equal(values.profiles[0].cid,1);assert.equal(Object.hasOwn(values.profiles[0],'password'),false);assert.equal(values.profiles[1].password,'replacement');
});
test('action field whitelist excludes unrelated secrets and fields',()=>{
 const model=parseSettings(settingsFixtures().cpi,'cpi'),draft=structuredClone(model.values);draft.key_password='secret';
 assert.deepEqual(serializeSettings(model,draft,new Set([pathKey(['key_password'])]),[]),{});
 assert.deepEqual(serializeSettings(model,draft,new Set(),['latitude']),{latitude:41});
});
test('an action sends only its own fields, so adding a key never sends the removal choice',()=>{
 const model=parseSettings(settingsFixtures().ssh,'ssh'),draft=structuredClone(model.values);draft.name='Field laptop';draft.key='ssh-ed25519 AAAA fixture';
 const add=model.actions.find(action=>action.id==='ssh.add'),remove=model.actions.find(action=>action.id==='ssh.remove');
 assert.deepEqual(serializeSettings(model,draft,new Set(),add.fields),{name:'Field laptop',key:'ssh-ed25519 AAAA fixture'});
 assert.deepEqual(serializeSettings(model,draft,new Set(),remove.fields),{remove:'SHA256:fixtureOperatorKey'});
 assert.equal(model.actions.some(action=>action.kind==='save'),false);
});
test('readback must match persisted fields, including list contents, but not write-only secrets',()=>{
 const model=parseSettings(settingsFixtures().apn,'apn'),wanted=structuredClone(model.values),actual=structuredClone(model.values);wanted.profiles[0].password='new';
 assert.equal(readbackMatches(model.fields,wanted,actual),true);actual.profiles[0].apn='different';assert.equal(readbackMatches(model.fields,wanted,actual),false);
});
test('foreign actions, unsafe field keys and missing revision fail closed',()=>{
 for(const mutate of [m=>m.revision='',m=>m.actions[0].id='restart.reboot',m=>m.fields[0].id='__proto__',m=>m.fields[0].type='html']){
  const model=settingsFixtures().services;mutate(model);assert.throws(()=>parseSettings(model,'services'),/invalid settings/);
 }
});

test('new list rows accept device-assigned identity while existing identity must match',()=>{
 const model=parseSettings(settingsFixtures().apn,'apn'),wanted=structuredClone(model.values),actual=structuredClone(model.values);
 wanted.profiles[0].cid=null;actual.profiles[0].cid=4;assert.equal(readbackMatches(model.fields,wanted,actual),true);
 actual.profiles[1].cid=5;assert.equal(readbackMatches(model.fields,wanted,actual),false);
});

test('allocated list identities may reorder rows without hiding changed data',()=>{
 const model=parseSettings(settingsFixtures().apn,'apn'),wanted=structuredClone(model.values);wanted.profiles[0].cid=null;
 const actual=structuredClone(wanted);actual.profiles[0].cid=4;actual.profiles.reverse();
 assert.equal(readbackMatches(model.fields,wanted,actual),true);actual.profiles[0].apn='wrong';assert.equal(readbackMatches(model.fields,wanted,actual),false);
});
