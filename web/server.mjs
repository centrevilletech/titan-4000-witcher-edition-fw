import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('./dist/', import.meta.url));
const types = {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.woff2':'font/woff2','.woff':'font/woff'};
const server=createServer(async(req,res)=>{
 if(!['GET','HEAD'].includes(req.method)){res.writeHead(405);return res.end('Read-only walkthrough');}
 try {
  const pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname);
  const path=resolve(root,'.'+(pathname==='/'?'/index.html':pathname));
  if(!path.startsWith(root.endsWith(sep)?root:root+sep)){res.writeHead(403);return res.end();}
  const body=await readFile(path);
  res.writeHead(200,{'Content-Type':types[extname(path)]||'application/octet-stream','Cache-Control':'no-cache','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; object-src 'none'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'"});
  res.end(req.method==='HEAD'?undefined:body);
 } catch {res.writeHead(404);res.end('Not found');}
});
server.listen(Number(process.env.PORT||4180),'127.0.0.1',()=>console.log('Titan walkthrough on http://127.0.0.1:'+(process.env.PORT||4180)));
