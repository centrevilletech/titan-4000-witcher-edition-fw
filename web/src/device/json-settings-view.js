import {apiFetch,jsonRequest} from './json-client.js';
import {probeFirmwareReturn,readServedVersion,rememberFirmwareReturn,freshFirmwareUrl} from './firmware-reconnect.js';
import {SessionExpired} from './errors.js';
import {SECTIONS,clone,pathKey,getValue,setValue,fieldAvailable,fieldEnabled,parseSettings,defaultRow,serializeSettings,readbackMatches} from './settings-model.js';
import {morphHTML} from '../morph.js';

const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const text=value=>value===null||value===undefined||value===''?'—':typeof value==='boolean'?(value?'Yes':'No'):String(value);
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const loading='<div class="settings-loading card card-pad" role="status" aria-live="polite"><span class="settings-loader" aria-hidden="true"></span><strong>Reading device settings</strong><p>Getting the current configuration from your Titan.</p><div class="skeleton-fields" aria-hidden="true"><i></i><i></i><i></i><i></i></div></div>';

// Last device reading per section for this sign-in. A screen opens on the
// cached reading at once and refreshes in place; it never flashes a loader for
// a section that has been read before.
const cache=new Map(),pending=new Map();
let cacheEpoch=0;
const fingerprint=model=>JSON.stringify([model.revision,model.values,model.fields,model.tables,model.actions,model.status,model.groups]);
export function clearSettingsCache(){cacheEpoch++;cache.clear();pending.clear();}
export function cachedSettings(section){return cache.get(section)?.model;}
export function prefetchSettings(section,{maxAge=0}={}){
 if(!SECTIONS.includes(section))return Promise.resolve(null);
 const entry=cache.get(section);if(entry&&Date.now()-entry.at<=maxAge)return Promise.resolve(entry.model);
 if(pending.has(section))return pending.get(section);
 const epoch=cacheEpoch;
 const request=jsonRequest('/api/v1/settings/'+section,{signal:AbortSignal.timeout(15000)}).then(value=>{
  const model=parseSettings(value,section);if(epoch===cacheEpoch)cache.set(section,{model,at:Date.now()});return model;
 }).finally(()=>{if(pending.get(section)===request)pending.delete(section);});
 pending.set(section,request);request.catch(()=>{});
 return request;
}

// Schemas and typed JSON are the entire device interface. This module never
// loads, parses, executes, or submits a vendor page and never creates an iframe.
export class JsonSettingsView {
 constructor(h){this.h=h;this.host=null;this.serial=0;this.busy=false;this.model=null;this.controls=new Map();this.files=new Map();this.secrets=new Set();}
 destroy(){this.serial++;this.abort?.abort();clearTimeout(this.timer);this.host=null;this.busy=false;this.files.clear();this.secrets.clear();}
 theme(){}
 async mount(host,section){
  this.destroy();this.host=host;this.section=section;this.abort=new AbortController();this.restarting=false;this.lastError=null;this.model=null;const generation=this.serial;
  host.oninput=event=>this.input(event);host.onchange=event=>this.input(event);host.onclick=event=>this.click(event);
  host.onsubmit=event=>{event.preventDefault();const action=this.model?.actions.find(a=>a.kind==='save'&&a.enabled!==false);if(action)this.perform(action);};
  // Rendered synchronously so a view transition captures the finished screen.
  const cached=cache.get(section);
  if(cached){this.accept(cached.model,{silent:true});if(Date.now()-cached.at<1500)return;}
  else host.innerHTML=loading;
  try{if(!SECTIONS.includes(section))throw new Error('Unknown settings section.');const model=await this.read();if(generation!==this.serial)return;if(!cached||!this.h.state.dirty&&!this.busy)this.accept(model,{silent:true});}
  catch(error){if(generation===this.serial)this.handleError(error,!cached);}
 }
 signal(timeout=15000){return AbortSignal.any([this.abort.signal,AbortSignal.timeout(timeout)]);}
 async read(){const model=parseSettings(await jsonRequest('/api/v1/settings/'+this.section,{signal:this.signal()}),this.section);cache.set(this.section,{model,at:Date.now()});return model;}
 accept(model,{silent=false}={}){
  // Identical readings leave the screen untouched.
  if(silent&&this.model&&fingerprint(this.model)===fingerprint(model)&&!this.h.state.dirty){this.model=model;this.schedule();return;}
  this.model=model;this.draft=clone(model.values);this.files.clear();this.secrets.clear();this.h.state.dirty=false;this.render();this.schedule();
 }
 schedule(){
  clearTimeout(this.timer);const period=Number(this.model?.poll_after_ms);if(!Number.isFinite(period)||period<=0)return;
  this.timer=setTimeout(async()=>{
   const generation=this.serial;
   try{if(this.host?.isConnected&&!this.busy&&!this.h.state.dirty&&!document.hidden){const model=await this.read();if(generation===this.serial&&!this.busy&&!this.h.state.dirty)this.accept(model,{silent:true});}}
   catch(error){if(generation===this.serial)this.handleError(error);}
   finally{if(generation===this.serial)this.schedule();}
  },Math.max(1000,Math.min(60000,period)));
 }
 field(field,path=[field.id],local=this.draft){
  if(!fieldAvailable(field,this.draft,local))return '';
  const key=pathKey(path),value=field.client_value==='local_datetime'?new Date().toLocaleString():getValue(this.draft,path),id='json-control-'+this.controls.size;
  this.controls.set(id,{field,path});
  const disabled=this.busy||!fieldEnabled(field,this.draft,local);
  const common=`id="${id}" data-control="${esc(path.join('.'))}" data-json-control="${id}" aria-label="${esc(field.label)}" ${disabled?'disabled':''} ${field.readonly?'readonly':''} ${field.required?'required':''}`;
  const help=field.help?`<small>${esc(field.help)}</small>`:'';
  if(field.type==='readonly')return `<div class="device-reading ${field.multiline?'device-wide':''}"><dt>${esc(field.label)}</dt><dd ${field.client_value==='local_datetime'?'data-client-value="local_datetime"':''}>${esc(text(value))}</dd></div>`;
  if(field.type==='list'){
   const rows=Array.isArray(value)?value:[],max=field.max_items??64,min=field.min_items??0;
   return `<div class="device-entries device-wide" data-list="${esc(field.id)}">${rows.map((row,index)=>`<section class="device-entry"><div class="device-entry-title">${esc(field.item_label||'Entry')} ${index+1}</div><div class="device-fields">${field.fields.map(f=>this.field(f,[...path,index,f.id],row)).join('')}</div><div class="device-entry-actions">${field.removable===false?'':`<button type="button" class="btn" data-list-remove="${id}" data-row-index="${index}" ${disabled||rows.length<=min?'disabled':''}>Remove entry</button>`}</div></section>`).join('')||'<p class="settings-empty">No entries configured.</p>'}${field.addable===false?'':`<button type="button" class="btn" data-list-add="${id}" ${disabled||rows.length>=max?'disabled':''}>${esc(field.add_label||'Add entry')}</button>`}${help}</div>`;
  }
  if(field.type==='checkbox')return `<label class="device-toggle" for="${id}"><span>${esc(field.label)}${help}</span><input type="checkbox" ${common} ${value===true?'checked':''} ${field.readonly?'disabled':''}></label>`;
  let control;
  if(field.type==='select')control=`<select ${common}>${(field.options||[]).map(option=>`<option value="${esc(option.value)}" ${String(option.value)===String(value)?'selected':''} ${option.disabled?'disabled':''}>${esc(option.label)}</option>`).join('')}</select>`;
  else if(field.type==='textarea')control=`<textarea ${common} rows="${field.rows|| (field.readonly?12:4)}" ${field.max_length?`maxlength="${field.max_length}"`:''}>${esc(value??'')}</textarea>`;
  else if(field.type==='file')control=`<input type="file" ${common} ${field.accept?`accept="${esc(field.accept)}"`:''} ${field.multiple?'multiple':''}>${this.files.has(key)?`<small>${[...this.files.get(key)].map(file=>esc(file.name)).join(', ')}</small>`:''}`;
  else control=`<input type="${field.type}" ${common} value="${esc(field.type==='password'?(this.secrets.has(key)?value??'':''):value??'')}" ${field.min!==undefined?`min="${esc(field.min)}"`:''} ${field.max!==undefined?`max="${esc(field.max)}"`:''} ${field.type==='number'?`step="${esc(field.step??'any')}"`:''} ${field.max_length?`maxlength="${field.max_length}"`:''} placeholder="${esc(field.placeholder||(field.type==='password'&&field.secret_set?'Unchanged':''))}" ${field.type==='password'?'autocomplete="new-password" spellcheck="false"':''}>`;
  return `<label class="field device-field ${field.type==='textarea'?'device-wide':''}"><span>${esc(field.label)}</span>${control}${help}</label>`;
 }
 table(table){
  const columns=table.columns||[],rows=table.rows||[];
  return `${table.title?`<h3 class="device-wide">${esc(table.title)}</h3>`:''}<div class="device-table-wrap device-wide"><table><thead><tr>${columns.map(c=>`<th>${esc(c.label)}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${columns.map((c,i)=>`<td>${esc(text(Array.isArray(row)?row[i]:row[c.key]))}</td>`).join('')}</tr>`).join('')||`<tr><td colspan="${Math.max(1,columns.length)}">No entries available.</td></tr>`}</tbody></table></div>`;
 }
 button(action){return `<button type="button" class="btn ${action.kind==='save'?'btn-primary':''}" data-json-action="${esc(action.id)}" ${this.busy||action.enabled===false||action.kind==='save'&&this.model.capabilities?.write===false?'disabled':''} ${action.help?`title="${esc(action.help)}"`:''}>${esc(action.label)}</button>`;}
 render(){
  if(!this.host?.isConnected||!this.model)return;
  this.controls.clear();const model=this.model,groupIds=new Set(model.groups.map(g=>g.id));
  for(const entry of [...model.fields,...model.tables,...model.actions])if(entry.group)groupIds.add(entry.group);
  const groups=[...groupIds].map(id=>model.groups.find(g=>g.id===id)||{id,title:id});
  const group=(definition,id)=>{
   const fields=model.fields.filter(field=>(field.group||'')===id).map(field=>this.field(field)).join('');
   const tables=model.tables.filter(table=>(table.group||'')===id).map(table=>this.table(table)).join('');
   const actions=id?model.actions.filter(action=>action.group===id).map(action=>this.button(action)).join(''):'';
   if(!fields&&!tables&&!actions)return '';
   return `<section class="card card-pad device-section">${definition?`<header><h2>${esc(definition.title)}</h2>${definition.description?`<p>${esc(definition.description)}</p>`:''}</header>`:''}<div class="device-fields">${fields}${tables}${actions?`<div class="device-inline-actions device-wide">${actions}</div>`:''}</div></section>`;
  };
  const html=`<form class="device-settings" data-settings-ready data-settings-tab="${esc(this.section)}" data-dirty="${this.h.state.dirty}"><div class="device-error" role="alert" ${this.lastError?'':'hidden'}>${esc(this.lastError||'')}</div>${groups.map(g=>group(g,g.id)).join('')}${group(null,'')}${model.status?.message?`<p class="settings-capability" role="status">${esc(model.status.message)}</p>`:''}<div class="device-savebar"><span data-save-status>${this.h.state.dirty?'Unsaved changes':'Read from device'}</span><div><button type="button" class="btn" data-settings-reload ${this.busy?'disabled':''}>${this.h.state.dirty?'Discard':'Reload'}</button>${model.actions.filter(a=>!a.group).map(a=>this.button(a)).join('')}</div></div></form>`;
  const form=this.host.querySelector(':scope>[data-settings-ready]');
  if(form&&form.dataset.settingsTab===this.section)morphHTML(this.host,html);
  else{const arriving=!!this.host.querySelector(':scope>.settings-loading');this.host.innerHTML=html;if(arriving)this.host.firstElementChild.classList.add('settings-arrive');}
  for(const [id,{field,path}]of this.controls){
   if(field.type!=='file')continue;const files=this.files.get(pathKey(path)),input=this.host.querySelector('#'+id);
   if(!files?.length){if(input?.files.length)input.value='';continue;}
   if(input){const transfer=new DataTransfer();files.forEach(file=>transfer.items.add(file));input.files=transfer.files;}
  }
  this.h.loaded?.();
 }
 markDirty(){this.h.state.dirty=this.model.capabilities?.write!==false;const form=this.host.querySelector('[data-settings-ready]');if(form)form.dataset.dirty=String(this.h.state.dirty);const reload=this.host.querySelector('[data-settings-reload]');if(reload)reload.textContent=this.h.state.dirty?'Discard':'Reload';const status=this.host.querySelector('[data-save-status]');if(status)status.textContent=this.h.state.dirty?'Unsaved changes':'Ready';}
 update(){for(const element of this.host?.querySelectorAll('[data-client-value="local_datetime"]')||[]){const value=new Date().toLocaleString();if(element.textContent!==value)element.textContent=value;}}
 input(event){
  const control=this.controls.get(event.target.dataset.jsonControl);if(!control||this.busy)return;
  const {field,path}=control,key=pathKey(path),element=event.target;
  if(field.readonly||field.type==='readonly')return;
  if(field.type==='file')this.files.set(key,[...element.files]);
  else{setValue(this.draft,path,field.type==='checkbox'?element.checked:element.value);if(field.type==='password')this.secrets.add(key);}
  this.markDirty();
  if(event.type==='change'&&(field.type==='select'||field.type==='checkbox')){this.render();this.host.querySelector(`[data-control="${CSS.escape(path.join('.'))}"]`)?.focus({preventScroll:true});}
 }
 click(event){
  const button=event.target.closest('[data-json-action],[data-settings-reload],[data-list-add],[data-list-remove]');if(!button||this.busy||button.disabled)return;event.preventDefault();
  if(button.hasAttribute('data-settings-reload')){this.reload(button);return;}
  if(button.dataset.listAdd||button.dataset.listRemove){
   const control=this.controls.get(button.dataset.listAdd||button.dataset.listRemove);if(!control)return;const {field,path}=control,rows=getValue(this.draft,path)||[];
   if(button.dataset.listAdd){if(rows.length>=(field.max_items??64))return;rows.push(defaultRow(field.fields));}
   else{
    if(rows.length<=(field.min_items??0))return;const removed=Number(button.dataset.rowIndex);rows.splice(removed,1);
    const remap=key=>{const current=JSON.parse(key);if(path.every((part,index)=>current[index]===part)){if(current[path.length]===removed)return null;if(current[path.length]>removed)current[path.length]--;}return pathKey(current);};
    this.files=new Map([...this.files].map(([key,files])=>[remap(key),files]).filter(([key])=>key!==null));
    this.secrets=new Set([...this.secrets].map(remap).filter(key=>key!==null));
   }
   setValue(this.draft,path,rows);this.markDirty();this.render();return;
  }
  const action=this.model.actions.find(a=>a.id===button.dataset.jsonAction);if(action)this.perform(action);
 }
 // Reload refreshes in place: the button shows progress and the form stays put.
 async reload(button){
  const generation=this.serial;
  if(!this.model){this.mount(this.host,this.section);return;}
  button.disabled=true;button.classList.add('is-working');
  try{const model=await this.read();if(generation!==this.serial)return;this.h.state.dirty=false;this.lastError=null;this.accept(model);this.h.toast('Settings read from the Titan.');}
  catch(error){if(generation===this.serial)this.handleError(error);}
  finally{if(generation===this.serial){button.disabled=false;button.classList.remove('is-working');}}
 }
 async download(action){
  const response=await apiFetch('/api/v1/downloads/'+encodeURIComponent(action.id),{signal:this.signal(60000),headers:{Accept:'application/octet-stream'}});
  const blob=await response.blob(),link=document.createElement('a');link.href=URL.createObjectURL(blob);
  link.download=response.headers.get('content-disposition')?.match(/filename="?([^";]+)"?/)?.[1]||action.filename||'titan-backup.bin';link.click();setTimeout(()=>URL.revokeObjectURL(link.href),2000);
 }
 async operation(result,generation){
  let operation=result.operation;
  if(!operation)return result;
  const started=Date.now();
  while(['pending','running'].includes(operation.state)){
   if(!operation.id||Date.now()-started>180000)throw new Error('The device has not confirmed completion. Check its current state before retrying.');
   const status=this.host?.querySelector('[data-save-status]');if(status)status.textContent=operation.message||'Waiting for device…';
   await pause(750);if(generation!==this.serial)throw new Error('Operation view closed.');
   result=await jsonRequest('/api/v1/operations/'+encodeURIComponent(operation.id),{signal:this.signal()});operation=result.operation||result;
  }
  if(operation.state!=='succeeded')throw new Error(operation.message||(operation.state==='uncertain'?'The operation outcome is uncertain. Check the device before retrying.':'The device could not complete the operation.'));
  return result;
 }
 firmwareProgress(message){
  this.host.innerHTML=`<section class="card card-pad" role="status" aria-live="polite"><h2>Updating firmware</h2><p data-save-status>${esc(message)}</p><p>Keep power connected. Installation and verification can take several minutes. This page will follow the restart automatically.</p></section>`;
 }
 async reconnectFirmware(generation,{uncertain=false}={}){
  this.restarting=true;
  const boot=this.model?.values?.boot_id;
  this.h.state.dirty=false;
  this.host.innerHTML=`<div class="card card-pad" role="status" aria-live="polite"><h2>${uncertain?'Checking the device after disconnection':'Restarting your Titan'}</h2><p>${uncertain?'The connection ended before the final update response. Checking for a restart; the upload will not be repeated.':'The image was verified and restart requested. The page will reload automatically when the device returns.'}</p><p>Keep power connected. Stock firmware can take several minutes to start its web interface.</p><p data-reconnect-status>Waiting for the device to restart…</p><p><a href="/" target="_self">Open the device again</a></p></div>`;
  const deadline=Date.now()+600000;
  while(generation===this.serial&&Date.now()<deadline){
   await pause(3000);if(generation!==this.serial)return;
   const returned=await probeFirmwareReturn(boot,fetch,this.signal(5000));
   if(returned&&generation===this.serial){
    if(returned==='witcher'){
     const version=await readServedVersion(fetch,this.signal(5000));
     if(generation!==this.serial)return;
     if(version)rememberFirmwareReturn(version,'restarted');
    }
    this.host.querySelector('[data-reconnect-status]').textContent='Device returned. Loading its current firmware…';
    window.location.replace(freshFirmwareUrl());return;
   }
  }
  if(generation===this.serial)this.host.querySelector('[data-reconnect-status]').textContent='The browser has not confirmed the restart. Check the device address and connection before retrying any firmware operation.';
 }
 async perform(action){
  if(this.busy||action.enabled===false)return;
  const values=serializeSettings(this.model,this.draft,this.secrets,action.fields);
  if(action.kind!=='download')for(const element of this.host.querySelectorAll('input,textarea,select')){
   const field=this.controls.get(element.dataset.jsonControl)?.path[0];if(action.fields&&!action.fields.includes(field))continue;
   if(!element.reportValidity())return;
  }
  const run=async()=>{
   const generation=this.serial,originalDraft=clone(this.draft),originalSecrets=new Set(this.secrets),originalFiles=new Map(this.files),wasDirty=this.h.state.dirty;
   const originalValues=this.model.values,committed=action.kind==='save'?null:action.fields||[];
   let firmwareSubmitted=false;
   const firmwareRestart=this.section==='firmware'&&(action.id==='firmware.rollback'||action.id==='firmware.install'&&values.reboot!==false);
   this.busy=true;this.lastError=null;clearTimeout(this.timer);this.host.setAttribute('aria-busy','true');this.render();
   try{
    if(action.kind==='download'){await this.download(action);return;}
    for(const [key,source]of Object.entries(action.client_values||{}))if(source==='unix_time_seconds')values[key]=Math.floor(Date.now()/1000);
    const payload={section:this.section,revision:this.model.revision,values};
    const selected=[...this.files].filter(([key,files])=>files.length&&(!action.fields||action.fields.includes(JSON.parse(key)[0])));
    let result;
    if(selected.length){
     const body=new FormData();body.append('section',this.section);body.append('revision',this.model.revision);body.append('values',JSON.stringify(values));
     for(const [key,files]of selected){const path=JSON.parse(key),field=[...this.controls.values()].find(c=>pathKey(c.path)===key)?.field;for(const file of files){if(field?.max_size&&file.size>field.max_size)throw new Error(`${field.label} exceeds the maximum file size.`);body.append(path.join('.'),file,file.name);}}
     if(firmwareRestart){firmwareSubmitted=true;this.firmwareProgress('Uploading firmware…');}
     result=await jsonRequest('/api/v1/uploads/'+encodeURIComponent(action.id),{method:'POST',body,signal:this.signal(180000)});
    }else{
     if(firmwareRestart){firmwareSubmitted=true;this.firmwareProgress('Requesting firmware bank switch…');}
     result=await jsonRequest(action.kind==='save'?'/api/v1/settings/'+this.section:'/api/v1/actions/'+encodeURIComponent(action.id),{method:action.kind==='save'?'PUT':'POST',body:JSON.stringify(action.kind==='save'?{revision:payload.revision,values}:payload),signal:this.signal(60000)});
    }
    if(generation!==this.serial)return;
    result=await this.operation(result,generation);if(generation!==this.serial)return;
    if(this.section==='firmware'&&(result.operation?.rebooting||result.result?.rebooting)){await this.reconnectFirmware(generation);return;}
    const model=result.settings?parseSettings(result.settings,this.section):result.fields?parseSettings(result,this.section):await this.read();
    const output=result.output??result.result?.output;if(typeof output==='string'&&model.fields.some(field=>field.id==='output'&&(field.readonly||field.type==='readonly')))model.values.output=output;
    if(action.kind==='save'&&!readbackMatches(model.fields,values,model.values))throw new Error('The device returned different settings. Reload and review its current values before retrying.');
    cache.set(this.section,{model,at:Date.now()});
    this.accept(model);
    if(wasDirty&&committed){
     for(const field of model.fields){if(committed.includes(field.id))continue;if(JSON.stringify(originalDraft[field.id])!==JSON.stringify(originalValues[field.id])){this.draft[field.id]=originalDraft[field.id];this.h.state.dirty=true;}}
     for(const key of originalSecrets)if(!committed.includes(JSON.parse(key)[0]))this.secrets.add(key);
     for(const [key,files]of originalFiles)if(!committed.includes(JSON.parse(key)[0]))this.files.set(key,files);
    }
    this.h.toast(action.kind==='save'?'Settings saved and read back from the Titan.':result.operation?.message||result.message||'Device response received.');
   }catch(error){if(generation===this.serial){
    const disconnected=error.name==='TimeoutError'||error instanceof TypeError&&/fetch|network/i.test(error.message)||error instanceof SessionExpired||error.status===404;
    if(firmwareSubmitted&&disconnected){await this.reconnectFirmware(generation,{uncertain:true});return;}
    if(disconnected)error=new Error('The connection ended before the device confirmed the operation. Reload and check its current state before retrying.');
    this.handleError(error);
   }}
   finally{if(generation===this.serial){this.busy=false;this.host?.removeAttribute('aria-busy');if(!this.restarting){this.render();this.schedule();}}}
  };
  if(action.confirm)this.h.confirm(typeof action.confirm==='string'?action.confirm:`${action.label} on this Titan? This can interrupt service.`,run);else await run();
 }
 handleError(error,replace=false){if(error instanceof SessionExpired){this.h.expire();return;}this.lastError=error.status===409?'These settings changed on the Titan while you were editing. Reload them before saving.':error.message;
  if(!this.host?.isConnected)return;
  if(replace)this.host.innerHTML=`<section class="card card-pad"><h2>Settings unavailable</h2><p class="muted">${esc(this.lastError)}</p><button type="button" class="btn mt-4" data-settings-reload>Try again</button></section>`;
  else{const element=this.host.querySelector('.device-error');if(element){element.hidden=false;element.textContent=this.lastError;element.scrollIntoView({block:'nearest'});}}
 }
}
