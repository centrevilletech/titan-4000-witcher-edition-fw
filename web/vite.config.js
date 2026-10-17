import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';
import {fileURLToPath} from 'node:url';
import {readFileSync} from 'node:fs';
const version=readFileSync(new URL('../VERSION',import.meta.url),'utf8').trim();
if(!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/.test(version))throw new Error('VERSION must contain a semantic version');
export default defineConfig(({mode}) => {
 const device=['device','rust-device'].includes(mode);
 return {
  define:{__WITCHER_VERSION__:JSON.stringify(version)},
  resolve:{alias:{'#device-runtime':fileURLToPath(new URL('./src/device/json-runtime.js',import.meta.url))}},
  plugins:[tailwindcss(),{name:'device-description',transformIndexHtml(html){
   const description=device?html.replace('Titan 4000 Witcher Edition — interactive UI walkthrough with simulated data.','Titan 4000 device management and antenna alignment.'):html;
   return description.replace('</head>',`<meta name="witcher-version" content="${version}" />\n</head>`);
  }}],base:device?'/ui/':'/',build:{target:'es2020',outDir:device?'dist-device':'dist'}
 };
});
