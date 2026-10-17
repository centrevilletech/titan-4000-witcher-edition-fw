// Each preview test gets its existing browser isolation; one ephemeral server
// removes the need to run npm dev manually or reuse an unrelated workstation UI.
import {createServer} from 'vite';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const server=await createServer({server:{host:'127.0.0.1',port:0,watch:null,hmr:false}});
await server.listen();
try{
 const address=server.httpServer.address();
 for(const file of ['walkthrough.mjs','operator-settings.mjs','motion.mjs','refinements.mjs','align.mjs'])await new Promise((resolve,reject)=>{
  const child=spawn(process.execPath,[fileURLToPath(new URL(file,import.meta.url))],{stdio:'inherit',env:{...process.env,TITAN_PREVIEW_URL:`http://127.0.0.1:${address.port}`}});
  child.on('error',reject);child.on('exit',(code,signal)=>code===0?resolve():reject(new Error(`${file} failed: ${signal||code}`)));
 });
}finally{await server.close();}
