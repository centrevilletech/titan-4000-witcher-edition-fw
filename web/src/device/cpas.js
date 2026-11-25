// The SAS CPAS window, 06:45 to 10:15 UTC with a margin. The SAS issues no
// new grants in it, so a restart, a firmware change, a SAS action or a radio
// change made then can keep the unit off the air until it ends. It is the
// window the keeper's reboot gate waits out (userspace/pd-model/src/tk_boot.rs
// CPAS_QUIET); tests/cpas.test.mjs keeps the two equal.
export const CPAS_WINDOW={start:6*60+45,end:10*60+15};

// Actions that restart the unit, change its firmware, touch its SAS
// registration or grant, or re-attach LTE.
const OFF_AIR=new Set(['restart.reboot','restart.factory_reset','backup.restore','firmware.install','firmware.rollback','firmware.remote.install',
 'sas.save','sas.register','sas.relinquish','sas.deregister','apn.save','selection.save','selection.connect','selection.disconnect','lock.save','mode.save']);
export const offAir=id=>OFF_AIR.has(id)||id.startsWith('scan.');

const minutes=date=>date.getUTCHours()*60+date.getUTCMinutes();
const clock=m=>`${String(Math.floor(m/60)).padStart(2,'0')}:${String(m%60).padStart(2,'0')}`;
// The browser's clock, not the unit's: the unit boots at 2013 until the network sets it.
export const cpasOpen=(date=new Date())=>minutes(date)>=CPAS_WINDOW.start&&minutes(date)<CPAS_WINDOW.end;

// A warning for action `id` at `date`, or '' when none applies.
export function cpasWarning(id,date=new Date()){
 if(!offAir(id)||!cpasOpen(date))return '';
 const end=clock(CPAS_WINDOW.end);
 return `It is ${clock(minutes(date))} UTC, inside the SAS CPAS window (${clock(CPAS_WINDOW.start)}–${end} UTC). The SAS issues no new grants until ${end} UTC, so this can keep the unit off the air until then. Unless it is urgent, wait until after ${end} UTC.`;
}
