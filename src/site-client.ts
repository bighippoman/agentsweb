export const siteScript = String.raw`
'use strict';
const $=id=>document.getElementById(id);
for(const button of document.querySelectorAll('.copy-command')) button.addEventListener('click',async()=>{try{await navigator.clipboard.writeText('npx -y intercept-mcp');button.textContent='Copied';}catch{button.textContent='Select to copy';}});
if($('request-form')){
  let mode='fetch',view='readable',last=null,controller=null;
  const input=$('request-input'),output=$('output'),status=$('request-status');
  function setMode(next){mode=next;for(const b of document.querySelectorAll('[data-mode]'))b.setAttribute('aria-pressed',String(b.dataset.mode===mode));input.type=mode==='fetch'?'url':'text';$('input-label').textContent=mode==='fetch'?'Page URL':mode==='ask'?'Search indexed passages':'Research query';input.value=mode==='fetch'?'https://react.dev/reference/react/useState':mode==='ask'?'react useState':'React state updates';}
  for(const b of document.querySelectorAll('[data-mode]'))b.addEventListener('click',()=>setMode(b.dataset.mode));
  for(const b of document.querySelectorAll('[data-example]'))b.addEventListener('click',()=>{input.value=mode==='fetch'?(b.dataset.example==='react'?'https://react.dev/reference/react/useState':'https://docs.python.org/3/tutorial/controlflow.html'):(b.dataset.example==='react'?'react useState':'python for statement');input.focus();});
  function el(tag,text,cls){const node=document.createElement(tag);node.textContent=text;if(cls)node.className=cls;return node;}
  function inline(text,node){
    const pattern=/(\[[^\]\n]+\]\(https?:\/\/[^\s)]+\)|\*\*[^*]+\*\*|\x60[^\x60]+\x60)/g;let position=0;
    for(const match of text.matchAll(pattern)){
      node.append(document.createTextNode(text.slice(position,match.index)));const token=match[0];
      if(token.startsWith('[')){const link=token.match(/^\[([^\]]+)\]\((.+)\)$/);const a=el('a',link[1]);a.href=link[2];a.target='_blank';a.rel='noopener noreferrer';node.append(a);}
      else if(token.startsWith('**'))node.append(el('strong',token.slice(2,-2)));
      else node.append(el('code',token.slice(1,-1)));
      position=match.index+token.length;
    }
    node.append(document.createTextNode(text.slice(position)));return node;
  }
  function markdown(text,parent){
    let code=false,block='';
    for(const line of String(text).split('\n')){
      if(line.startsWith(String.fromCharCode(96,96,96))){if(code){parent.append(el('pre',block));block='';}code=!code;continue;}
      if(code){block+=line+'\n';continue;}
      const heading=line.match(/^(#{1,6})\s+(.+)/);
      if(heading)parent.append(inline(heading[2],el(heading[1].length<2?'h2':heading[1].length<3?'h3':'h4','')));
      else if(/^\s*[-*_]{3,}\s*$/.test(line))parent.append(el('hr',''));
      else if(line.trim())parent.append(inline(line,el('p','')));
    }
    if(block)parent.append(el('pre',block));
  }
  function render(){
    if(!last)return;output.replaceChildren();
    if(view==='json'){output.append(el('pre',JSON.stringify(last,null,2)));return;}
    if(last.error){output.append(el('p',last.error,'error'));return;}
    const items=last.results||[last];
    if(!items.length){output.append(el('h3','No matching passages yet.'),el('p','The cache only searches pages already indexed. Fetch a relevant URL, or use Research to discover sources.'));return;}
    for(const item of items){
      const article=el('article','');
      if(item.url){try{const url=new URL(item.citation_url||item.url);if(['https:','http:'].includes(url.protocol)){const a=el('a',item.title||item.heading||item.url);a.href=url.href;a.target='_blank';a.rel='noopener noreferrer';article.append(a);}}catch{}}
      if(item.markdown||item.text)markdown(item.markdown||item.text,article);
      else article.append(el('p',item.snippet||'Readable content was unavailable for this source.'));
      output.append(article);
    }
  }
  $('view-readable').addEventListener('click',()=>{view='readable';$('view-readable').setAttribute('aria-pressed','true');$('view-json').setAttribute('aria-pressed','false');render();});
  $('view-json').addEventListener('click',()=>{view='json';$('view-json').setAttribute('aria-pressed','true');$('view-readable').setAttribute('aria-pressed','false');render();});
  $('copy-output').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(view==='json'?JSON.stringify(last,null,2):last.markdown||JSON.stringify(last,null,2));$('copy-output').textContent='Copied';}catch{status.textContent='Copy unavailable; select the response text.';}});
  $('cancel').addEventListener('click',()=>controller?.abort());
  $('request-form').addEventListener('submit',async event=>{
    event.preventDefault();controller?.abort();controller=new AbortController();const active=controller;
    $('run').disabled=true;$('cancel').hidden=false;status.textContent='Retrieving sources…';output.setAttribute('aria-busy','true');$('evidence').hidden=true;
    const started=performance.now();const requestMode=mode;
    try{
      const params=new URLSearchParams(requestMode==='fetch'?{url:input.value}:{q:input.value,count:'3'});
      const response=await fetch('/'+requestMode+'?'+params,{signal:active.signal});
      const data=await response.json();if(active!==controller)return;last=data;
      const elapsed=performance.now()-started;status.textContent=(response.ok?'Completed in ':'Request failed · ')+(elapsed/1000).toFixed(2)+' s';
      const evidence=$('evidence');evidence.replaceChildren();
      const facts=[];
      if(data.source)facts.push(data.source);if(data.search_source)facts.push(data.search_source);
      if(data.completeness)facts.push(data.completeness);if(data.source_kind==='archive')facts.push('Historical snapshot');
      if(typeof data.age_seconds==='number')facts.push('Retrieved '+(data.age_seconds<60?data.age_seconds+'s':Math.floor(data.age_seconds/60)+'m')+' ago');
      if(typeof data.cached==='boolean')facts.push(data.cached?'Cache hit':'Fetched now');
      if(data.results)facts.push(data.results.length+' results');
      for(const fact of facts)evidence.append(el('span',fact,fact==='partial'?'partial':''));evidence.hidden=!facts.length;
      $('copy-output').disabled=false;$('copy-output').textContent='Copy';render();
    }catch(error){if(active!==controller)return;status.textContent=error.name==='AbortError'?'Request cancelled':'Request failed';output.replaceChildren(el('p',error.name==='AbortError'?'Cancelled. You can run another request.':'The request could not complete. Please try again.','error'));}
    finally{if(active===controller){$('run').disabled=false;$('cancel').hidden=true;output.removeAttribute('aria-busy');}}
  });
}
`;
