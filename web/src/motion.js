// Motion is presentational: state and readings always update immediately.
const preference = matchMedia('(prefers-reduced-motion: reduce)');
const running = new Set();
const liveAnimations = new WeakMap();
const liveText = new WeakMap();
const liveHtml = new WeakMap();
const dialogGeneration = new WeakMap();
let observer;
let screenKey;
let activeTransition;
let transitionGeneration = 0;
// True while a view transition renders: it already fades the whole screen, so
// per-card reveals would animate the same content twice.
let transitioning = false;
const ease = 'cubic-bezier(.2,.7,.2,1)';
export const reduceMotion = () => preference.matches || document.hidden;

function animate(element, frames, options = {}) {
 if (!element || reduceMotion() || !element.animate) return null;
 const animation = element.animate(frames, {duration:240,easing:ease,...options});
 running.add(animation);
 animation.addEventListener('finish',()=>running.delete(animation),{once:true});
 animation.addEventListener('cancel',()=>running.delete(animation),{once:true});
 return animation;
}
export function reveal(element, delay=0) {
 return animate(element,[{opacity:0,transform:'translateY(4px)'},{opacity:1,transform:'translateY(0)'}],{duration:320,delay,fill:'backwards'});
}
export function mountMotion(root, key) {
 observer?.disconnect();
 if (!root || key === screenKey) return;
 screenKey = key;
 if (transitioning || reduceMotion() || document.documentElement.classList.contains('auth-transition')) return;
 const elements=[...root.querySelectorAll('.page-head,.card,.metrics,.align-hint,.panel-tabs,.login-form')]
  .filter(el=>!el.parentElement?.closest('.card,.metrics'));
 if ('IntersectionObserver' in window) observer=new IntersectionObserver(entries=>{
  for(const entry of entries)if(entry.isIntersecting){reveal(entry.target);observer.unobserve(entry.target);}
 },{threshold:.08});
 for(const element of elements){
  const bounds=element.getBoundingClientRect();
  // The screen itself fades in as one piece; only content below the fold
  // reveals as it scrolls into view.
  if(bounds.top>=innerHeight)observer?.observe(element);
 }
}
export function setLiveText(element, value) {
 const next=String(value);
 const previous=liveText.get(element);
 if(previous===next)return;
 liveText.set(element,next);
 element.textContent=next;
 if(previous===undefined)return;
 liveAnimations.get(element)?.cancel();
 const animation=animate(element,[{opacity:.55},{opacity:1}],{duration:260});
 if(animation)liveAnimations.set(element,animation);
}
export function setLiveHTML(element, value) {
 const previous=liveHtml.get(element);
 if(previous===value)return;
 liveHtml.set(element,value);
 element.innerHTML=value;
 if(previous!==undefined){
  liveAnimations.get(element)?.cancel();
  const animation=animate(element,[{opacity:.65},{opacity:1}],{duration:200});
  if(animation)liveAnimations.set(element,animation);
 }
}
export function transitionContent(render, {auth=false,tab=null}={}) {
 const generation=++transitionGeneration;
 activeTransition?.skipTransition();
 document.documentElement.classList.toggle('auth-transition',auth);
 if(tab)document.documentElement.dataset.tabTransition=tab;else delete document.documentElement.dataset.tabTransition;
 if(reduceMotion()||!document.startViewTransition){document.documentElement.classList.remove('auth-transition');delete document.documentElement.dataset.tabTransition;render();return;}
 try {
  const transition=document.startViewTransition(()=>{
   if(generation!==transitionGeneration)return;
   transitioning=true;
   try{render();}finally{transitioning=false;}
  });
  activeTransition=transition;
  // Missing named elements (e.g. login), background tabs, or rapid navigation
  // may skip an animation. The state update still takes place.
  transition.ready.catch(()=>{});
  transition.finished.catch(()=>{}).finally(()=>{if(activeTransition===transition){activeTransition=null;document.documentElement.classList.remove('auth-transition');delete document.documentElement.dataset.tabTransition;}});
 } catch {document.documentElement.classList.remove('auth-transition');delete document.documentElement.dataset.tabTransition;render();}
}
// Screen and tab changes swap content in place: the old view leaves at once,
// the new one fades in, and the container eases between the two heights.
// Two layouts are never drawn over each other.
export function enter(element) {
 if(!element)return null;
 element.getAnimations().forEach(animation=>animation.cancel());
 // Starting partly visible avoids an empty frame between the two views.
 return animate(element,[{opacity:.4,transform:'translateY(4px)'},{opacity:1,transform:'none'}],{duration:200,easing:'cubic-bezier(.2,.7,.2,1)'});
}
export function swapContent(container, render) {
 const before=container?.isConnected?container.getBoundingClientRect().height:null;
 container?.getAnimations().forEach(animation=>animation.cancel());
 render();
 if(!container?.isConnected||before===null)return;
 enter(container);
 const after=container.getBoundingClientRect().height;
 if(Math.abs(after-before)<4||reduceMotion())return;
 container.style.overflow='clip';
 const animation=animate(container,[{height:before+'px'},{height:after+'px'}],{duration:260,easing:'cubic-bezier(.2,.7,.2,1)'});
 const release=()=>{container.style.overflow='';};
 if(animation){animation.addEventListener('finish',release,{once:true});animation.addEventListener('cancel',release,{once:true});}else release();
}
export function showDialog(modal, html) {
 dialogGeneration.set(modal,(dialogGeneration.get(modal)||0)+1);
 modal.getAnimations().forEach(animation=>animation.cancel());
 const wasOpen=modal.open;
 modal.innerHTML=`<div class="modal-inner">${html}</div>`;
 if(!wasOpen)modal.showModal();
 animate(wasOpen?modal.firstElementChild:modal,
  [{opacity:0,transform:'translateY(5px)'},{opacity:1,transform:'translateY(0)'}],{duration:200});
}
export function closeDialog(modal) {
 const generation=(dialogGeneration.get(modal)||0)+1;
 dialogGeneration.set(modal,generation);
 if(!modal.open)return;
 modal.getAnimations().forEach(animation=>animation.cancel());
 const animation=animate(modal,[{opacity:1},{opacity:0}],{duration:100});
 if(!animation){modal.close();return;}
 const finish=()=>{if(dialogGeneration.get(modal)===generation)modal.close();};
 animation.addEventListener('finish',finish,{once:true});
 animation.addEventListener('cancel',finish,{once:true});
}
preference.addEventListener('change',()=>{
 if(!preference.matches)return;
 observer?.disconnect();
 activeTransition?.skipTransition();
 for(const animation of [...running])animation.cancel();
});
document.addEventListener('visibilitychange',()=>{
 if(document.hidden){activeTransition?.skipTransition();for(const animation of [...running])animation.cancel();}
});
