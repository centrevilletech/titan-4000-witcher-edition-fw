// Patch a live subtree to match freshly rendered markup. Unchanged nodes keep
// their identity, focus, scroll position and running animations, so a refresh
// from the device never repaints the whole screen.
const formValue=(live,next)=>{
 const focused=live===document.activeElement;
 if(live instanceof HTMLInputElement){
  if(live.type==='file')return;
  if(live.type==='checkbox'||live.type==='radio'){live.checked=next.hasAttribute('checked');return;}
  const value=next.getAttribute('value')??'';
  if(!focused&&live.value!==value)live.value=value;
 }else if(live instanceof HTMLTextAreaElement){
  const value=next.value;
  if(!focused&&live.value!==value)live.value=value;
 }else if(live instanceof HTMLSelectElement){
  const option=[...next.options].find(o=>o.hasAttribute('selected'))||next.options[0];
  if(option&&live.value!==option.value)live.value=option.value;
 }
};
function attributes(live,next){
 for(const {name}of [...live.attributes])if(!next.hasAttribute(name))live.removeAttribute(name);
 for(const {name,value}of next.attributes)if(live.getAttribute(name)!==value)live.setAttribute(name,value);
}
function same(live,next){return live.nodeType===next.nodeType&&live.nodeName===next.nodeName&&(live.nodeType!==1||live.getAttribute('type')===next.getAttribute('type'));}
export function morphChildren(live,next){
 const liveNodes=[...live.childNodes],nextNodes=[...next.childNodes];
 nextNodes.forEach((node,index)=>{
  const current=liveNodes[index];
  if(!current){live.appendChild(node);return;}
  if(!same(current,node)){live.replaceChild(node,current);return;}
  if(node.nodeType===3||node.nodeType===8){if(current.nodeValue!==node.nodeValue)current.nodeValue=node.nodeValue;return;}
  if(node.nodeType!==1)return;
  attributes(current,node);
  if(current instanceof HTMLTextAreaElement){formValue(current,node);return;}
  morphChildren(current,node);
  formValue(current,node);
 });
 for(let i=liveNodes.length-1;i>=nextNodes.length;i--)liveNodes[i].remove();
}
export function morphHTML(live,html){
 const template=document.createElement('template');template.innerHTML=html;
 morphChildren(live,template.content);
}
