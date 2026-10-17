// Read-only probes. Never retry an upload or bank switch after a disconnect.
const noticeKey='witcher-firmware-return';
export async function readServedVersion(fetcher=fetch, signal) {
 try {
  const response=await fetcher('/ui/index.html',{cache:'no-store',credentials:'omit',signal});
  if(!response.ok)return null;
  return (await response.text()).match(/<meta\s+name="witcher-version"\s+content="([0-9A-Za-z.+-]+)"\s*\/?>/i)?.[1]||null;
 }catch{return null;}
}
export function rememberFirmwareReturn(version, reason, storage=sessionStorage) {
 try{storage.setItem(noticeKey,JSON.stringify({version,reason,at:Date.now()}));}catch{/* Storage is optional. */}
}
export function firmwareReturnNotice(version, storage=sessionStorage) {
 try{
  const notice=JSON.parse(storage.getItem(noticeKey));
  if(!notice||Date.now()-notice.at>600000||notice.version!==version)return '';
  return `${notice.reason==='updated'?'Firmware changed.':'Device restarted.'} Now running Witcher v${version}.`;
 }catch{return '';}
}
export function freshFirmwareUrl() {
 return '/?witcher_reload='+Date.now();
}
export function watchFirmwareVersion(current,{fetcher=fetch,canReload=()=>true,onChange,interval=15000}={}) {
 let stopped=false,checking=false;
 async function check(){
  if(stopped||checking||document.hidden||!canReload())return;
  checking=true;
  try{
   const version=await readServedVersion(fetcher,AbortSignal.timeout(5000));
   if(!stopped&&version&&version!==current&&canReload()){stop();onChange(version);}
  }finally{checking=false;}
 }
 function stop(){stopped=true;clearInterval(timer);document.removeEventListener('visibilitychange',check);window.removeEventListener('focus',check);}
 const timer=setInterval(check,interval);
 document.addEventListener('visibilitychange',check);window.addEventListener('focus',check);
 check();return stop;
}
export async function probeFirmwareReturn(previousBoot, fetcher=fetch, signal) {
 let health;
 try {
  const response=await fetcher('/api/v1/health',{cache:'no-store',credentials:'omit',signal});
  if(response.ok)health=await response.json();
 }catch{/* Stock firmware has no native JSON health endpoint. */}
 if(health?.service==='titan-api')return previousBoot&&health.boot_id&&health.boot_id!==previousBoot?'witcher':null;
 try {
  const response=await fetcher('/',{cache:'no-store',credentials:'omit',signal});
  if(!response.ok)return null;
  const html=await response.text();
  if(/<frameset\b/i.test(html)&&/Status\.asp/i.test(html)||/Global Telecom/i.test(html)&&/login\.cgi/i.test(html))return 'stock';
 }catch{/* Reboot or network path is still unavailable. */}
 return null;
}
