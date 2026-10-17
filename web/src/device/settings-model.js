export const SECTIONS=['apn','selection','lock','scan','mode','lan','firewall','forwards','routes','device','access','ssh','services','sas','cpi','sasStatus','backup','firmware','restart','ping','status'];
const types=new Set(['text','password','number','select','checkbox','textarea','readonly','file','list']);
const safeId=id=>typeof id==='string'&&/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(id)&&!['__proto__','prototype','constructor'].includes(id);
export const clone=value=>structuredClone(value);
export const pathKey=path=>JSON.stringify(path);
export function getValue(values,path){return path.reduce((value,key)=>value?.[key],values);}
export function setValue(values,path,value){let target=values;for(const key of path.slice(0,-1)){if(target[key]===undefined)target[key]={};target=target[key];}target[path.at(-1)]=value;}
export function conditionMatches(condition,values,local=values){
 if(!condition)return true;
 if(Array.isArray(condition))return condition.every(c=>conditionMatches(c,values,local));
 const value=Object.hasOwn(local,condition.field)?local[condition.field]:values[condition.field];
 if(Array.isArray(condition.in))return condition.in.some(v=>String(v)===String(value));
 return String(value)===String(condition.equals);
}
export function fieldAvailable(field,values,local=values){return !field.hidden&&conditionMatches(field.visible_when,values,local);}
export function fieldEnabled(field,values,local=values){return !field.disabled&&conditionMatches(field.enabled_when,values,local);}
export function parseSettings(value,section){
 const invalid=()=>{throw new Error('The Titan returned an invalid settings response. Reload before making changes.');};
 if(!SECTIONS.includes(section)||!value||value.section!==section||typeof value.revision!=='string'||!value.revision||!Array.isArray(value.fields)||!value.values||typeof value.values!=='object'||Array.isArray(value.values))invalid();
 const fields=(list,depth=0)=>{
  if(depth>3||list.length>256)invalid();const ids=new Set();
  for(const field of list){
   if(!safeId(field.id)||ids.has(field.id)||typeof field.label!=='string'||!types.has(field.type))invalid();ids.add(field.id);
   if(field.options&&(!Array.isArray(field.options)||field.options.some(o=>!o||typeof o.label!=='string'||!['string','number','boolean'].includes(typeof o.value))))invalid();
   if(field.type==='list'){if(!Array.isArray(field.fields))invalid();fields(field.fields,depth+1);}
  }
 };
 fields(value.fields);
 if(value.actions&&!Array.isArray(value.actions))invalid();
 for(const action of value.actions||[]){
  if(!safeId(action.id)||!action.id.startsWith(section+'.')||typeof action.label!=='string'||!['save','action','download'].includes(action.kind))invalid();
  if(action.client_values&&Object.entries(action.client_values).some(([key,source])=>!safeId(key)||source!=='unix_time_seconds'))invalid();
 }
 const result=clone({...value,actions:value.actions||[],groups:value.groups||[],tables:value.tables||[]});
 // Never render or resubmit secrets returned accidentally by an adapter.
 const clearSecrets=(fields,values)=>{for(const field of fields){if(field.type==='password'||field.type==='file')delete values[field.id];if(field.type==='list')for(const row of values[field.id]||[])clearSecrets(field.fields,row);}};
 clearSecrets(result.fields,result.values);
 return result;
}
export function defaultRow(fields){return Object.fromEntries(fields.filter(f=>f.type!=='file'&&f.type!=='readonly').map(f=>[f.id,f.default??(f.type==='checkbox'?false:f.type==='list'?[]:f.type==='select'?f.options?.[0]?.value??'':'')]));}
export function serializeSettings(model,draft,changedSecrets=new Set(),onlyFields){
 const serialize=(fields,values,path=[],nested=false)=>{
  const output={};
  for(const field of fields){
   const fieldPath=[...path,field.id];
   if(!nested&&onlyFields&&!onlyFields.includes(field.id))continue;
   if(field.type==='file'||field.type==='readonly'||field.readonly&&!nested||!fieldAvailable(field,draft,values)||!fieldEnabled(field,draft,values))continue;
   if(field.type==='password'&&!changedSecrets.has(pathKey(fieldPath)))continue;
   const value=values[field.id];if(value===undefined)continue;
   if(field.type==='list')output[field.id]=value.map((row,i)=>serialize(field.fields,row,[...fieldPath,i],true));
   else if(field.type==='number')output[field.id]=value===''?null:Number(value);
   else if(field.type==='checkbox')output[field.id]=Boolean(value);
   else output[field.id]=value;
  }
  return output;
 };
 return serialize(model.fields,draft);
}
export function readbackMatches(fields,expected,actual){
 for(const field of fields){
  if(field.type==='password'||field.type==='file'||!Object.hasOwn(expected,field.id))continue;
  const wanted=expected[field.id],got=actual[field.id];
  if(field.readonly&&(wanted===null||wanted===''))continue; // New rows receive their stable identity from the device.
  if(field.type==='list'){
   if(!Array.isArray(got)||got.length!==wanted.length)return false;
   const identity=field.fields.find(f=>f.readonly&&f.type!=='readonly');
   if(identity){
    const matched=new Set();
    for(const row of wanted){
     const id=row[identity.id],hasId=id!==null&&id!==undefined&&id!=='';
     const index=got.findIndex((actual,index)=>!matched.has(index)&&(!hasId||String(actual[identity.id])===String(id))&&readbackMatches(field.fields,row,actual));
     if(index<0)return false;matched.add(index);
    }
   }else if(wanted.some((row,i)=>!readbackMatches(field.fields,row,got[i])))return false;
  }else if(wanted===null?got!==null&&got!=='':String(wanted)!==String(got))return false;
 }
 return true;
}
