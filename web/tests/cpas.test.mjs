import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {CPAS_WINDOW,cpasOpen,cpasWarning,offAir} from '../src/device/cpas.js';

const at=(hour,minute)=>new Date(Date.UTC(2026,10,25,hour,minute));

test('the window is the keeper reboot gate\'s, tk_boot::CPAS_QUIET',()=>{
 const source=readFileSync(new URL('../../userspace/pd-model/src/tk_boot.rs',import.meta.url),'utf8');
 const match=source.match(/pub const CPAS_QUIET: QuietWindow = QuietWindow \{ start_min: (\d+) \* 60 \+ (\d+), end_min: (\d+) \* 60 \+ (\d+) \}/);
 assert.ok(match,'CPAS_QUIET is where the UI expects it');
 const [,sh,sm,eh,em]=match.map(Number);
 assert.deepEqual(CPAS_WINDOW,{start:sh*60+sm,end:eh*60+em});
});
test('open from 06:45 up to 10:15 UTC',()=>{
 assert.equal(cpasOpen(at(6,44)),false);assert.equal(cpasOpen(at(6,45)),true);
 assert.equal(cpasOpen(at(10,14)),true);assert.equal(cpasOpen(at(10,15)),false);
});
test('restarts, firmware, SAS and radio actions warn inside the window only',()=>{
 for(const id of ['restart.reboot','restart.factory_reset','firmware.install','firmware.rollback','firmware.remote.install','backup.restore','sas.save','sas.register','sas.relinquish','sas.deregister','apn.save','selection.save','selection.connect','selection.disconnect','lock.save','mode.save','scan.refresh']){
  assert.equal(offAir(id),true,id);
  assert.match(cpasWarning(id,at(7,30)),/^It is 07:30 UTC, inside the SAS CPAS window \(06:45–10:15 UTC\)\. The SAS issues no new grants until 10:15 UTC/,id);
  assert.equal(cpasWarning(id,at(10,15)),'',id);assert.equal(cpasWarning(id,at(6,44)),'',id);
 }
 for(const id of ['ssh.add','latency.save','routes.save','lan.save','access.save','device.sync_time','ping.run','latency.retry'])assert.equal(cpasWarning(id,at(7,30)),'',id);
});
