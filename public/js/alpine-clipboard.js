/**
 * Minified by jsDelivr using Terser v5.19.2.
 * Original file: /npm/@ryangjchandler/alpine-clipboard@2.3.0/src/index.js
 *
 * Do NOT use SRI with dynamically generated files! More information: https://www.jsdelivr.com/using-sri-with-dynamic-files
 */
let onCopy=()=>{};const copy=(o,e=void 0)=>("function"==typeof o&&(o=o()),"object"==typeof o&&(o=JSON.stringify(o)),void 0!==e?window.navigator.clipboard.write([new ClipboardItem({[e]:new Blob([o],{type:e})})]).then(onCopy):window.navigator.clipboard.writeText(o).then(onCopy));function Clipboard(o){o.magic("clipboard",(()=>copy)),o.directive("clipboard",((o,{modifiers:e,expression:i},{evaluateLater:n,cleanup:t})=>{const p=e.includes("raw")?o=>o(i):n(i),r=()=>p(copy);o.addEventListener("click",r),t((()=>{o.removeEventListener("click",r)}))}))}Clipboard.configure=o=>(o.hasOwnProperty("onCopy")&&"function"==typeof o.onCopy&&(onCopy=o.onCopy),Clipboard);export default Clipboard;
//# sourceMappingURL=/sm/b0c58639a752e521b1b91d709d419bc94da7bbbb4b45ecef03e067a8ceed6479.map
