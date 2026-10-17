import {SessionExpired,ApiError} from './errors.js';

// In-memory only: the session cookie stays HttpOnly and the token is never saved.
let csrfToken;
export async function apiFetch(path, options={}) {
 const multipart=typeof FormData!=='undefined'&&options.body instanceof FormData;
 const response=await fetch(path,{credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(3000),...options,
  headers:{Accept:'application/json',...(options.body&&!multipart?{'Content-Type':'application/json'}:{}),...(options.method&&options.method!=='GET'&&csrfToken?{'X-CSRF-Token':csrfToken}:{}),...options.headers}});
 if(response.status===401){csrfToken=undefined;throw new SessionExpired('Sign in to continue.');}
 if(!response.ok){let details;try{details=await response.json();}catch{}const message=typeof details?.error==='string'?details.error:details?.error?.message||details?.message;throw new ApiError(message||`Titan returned HTTP ${response.status}.`,response.status,details);}
 return response;
}
export async function jsonRequest(path, options={}) {
 const response=await apiFetch(path,options);
 if(response.status===204)return null;
 if(!response.headers.get('content-type')?.includes('application/json'))throw new Error('The Titan returned an invalid API response.');
 return response.json();
}
export async function session(password) {
 const result=await jsonRequest('/api/v1/session',password===undefined?{}:{method:'POST',body:JSON.stringify({password}),signal:AbortSignal.timeout(35000)});
 if(result?.authenticated!==true)throw new SessionExpired('Sign in to continue.');
 csrfToken=result.csrf_token;
 return result;
}
export async function logout(){await jsonRequest('/api/v1/session',{method:'DELETE'});csrfToken=undefined;}

export function parseJsonTelemetry(value) {
 const invalid=()=>{throw new Error('The Titan returned an incomplete telemetry response.');};
 if(!value||!Number.isSafeInteger(value.sequence)||value.sequence<0||!Number.isFinite(value.age_ms)||value.age_ms<0||typeof value.stale!=='boolean')invalid();
 const t=value.telemetry;
 if(!t||typeof t.attached!=='boolean'||!Number.isFinite(t.session)||t.session<0||!Array.isArray(t.chains)||t.chains.some(v=>v!==null&&!Number.isFinite(v)))invalid();
 for(const key of ['rsrp','sinr','rsrq','pci','ethernet'])if(t[key]!==null&&!Number.isFinite(t[key]))invalid();
 for(const key of ['serial','model','firmware','mac','mode','name','mgmt','customer','customerV6','band','earfcn','plmn','ipType','registration','grant','cbsdId','grantId','sasError'])if(typeof t[key]!=='string')invalid();
 return value;
}

// Track source collection time, not the last successful browser request. Repeated
// cache reads can only make a sample older, even if a server reports age_ms=0.
export class SampleClock {
 constructor(){this.sequence=null;this.sampledAt=0;this.stale=true;}
 accept(sample, now=Date.now(), roundTripMs=0){
  const changed=sample.sequence!==this.sequence;
  const collected=now-sample.age_ms-Math.max(0,roundTripMs);
  this.sampledAt=changed?collected:Math.min(this.sampledAt,collected);
  this.sequence=sample.sequence;this.stale=sample.stale;
  return changed;
 }
 fresh(now=Date.now()){return !this.stale&&now-this.sampledAt<8000;}
}
