'use strict';
const $ = id => document.getElementById(id);
let csrf='', state=null, tab='wizard', peerFile=null, peerPass='', invitationAccepted=false;
const hiddenSeries = new Set();
let peerRates=new Map(), busy=false, polling=false, exchangeStep=null, lastStep=null;
const labels = {profile:'Site details',invitation:'Hub invitation',request:'Spoke request',approval:'Hub approval',activate:'Activate'};
function note(text){$('notice').textContent=text||''}
function show(id,yes){$(id).hidden=!yes}
async function api(path,value){
 const response=await fetch('/api/'+path,{method:value===undefined?'GET':'POST',headers:value===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:value===undefined?undefined:JSON.stringify(value)});
 const result=await response.json();
 if(!response.ok||!result.ok){if(response.status===401){show('login',true);show('workspace',false);show('navigation',false)}throw Error(result.error||(result.errors||[]).join('; ')||'Operation failed')}
 if(result.csrf)csrf=result.csrf;return result;
}
function card(parent,title,detail){const box=document.createElement('div');box.className='card';const heading=document.createElement('strong');heading.textContent=title;box.append(heading,document.createTextNode('\n'+detail));parent.append(box)}
function options(id,rows){const select=$(id),old=select.value;select.replaceChildren();for(const[value,label]of rows){const o=document.createElement('option');o.value=value;o.textContent=label;select.append(o)}if(rows.some(r=>r[0]===old))select.value=old}
function navigate(page){if(!state?.workflow.complete&&page!=='wizard')return;tab=page;exchangeStep=null;window.scrollTo({top:0,behavior:'instant'});render()}
function currentStep(){
 if(!state.configured)return state.role==='spoke'&&!invitationAccepted?'invitation':'profile';
 if(state.workflow.complete&&state.role==='spoke')return exchangeStep||'request';
 return exchangeStep||state.workflow.step;
}
function render(){
 const s=state,complete=s.workflow.complete,hub=s.role==='hub';
 if(!complete)tab='wizard';
 for(const name of ['wizard','monitor','topology','settings'])show(name+'Panel',tab===name);
 document.querySelectorAll('[data-tab]').forEach(b=>{b.disabled=!complete&&b.dataset.tab!=='wizard';b.setAttribute('aria-current',b.dataset.tab===tab?'page':'false')});
 $('setupNav').textContent=complete?(hub?'Connections':'Exchange files'):'Initial setup';
 $('roleBadge').textContent=s.role;
 $('siteTitle').textContent=s.label||'Network ready';
 $('pageTitle').textContent=tab==='wizard'?(complete?(hub?'Connect another Spoke':'Exchange peer files'):(hub?'Set up your Hub':'Connect your Spoke')):({monitor:'Your network, at a glance',topology:'Network topology',settings:'Appliance settings'}[tab]);
 $('pageSubtitle').textContent=tab==='wizard'?'One step at a time. Your private keys stay on this appliance.':(s.label||'Parto')+' · '+(s.obfuscated?'TLS + BGP (NG)':s.transport?.toUpperCase()+' + BGP')+' · Updated every 5 seconds';
 $('addresses').replaceChildren();for(const i of s.interfaces)card($('addresses'),i.name,i.addresses.join('\n')||'No global address');
 show('policy',hub);show('lan',!hub);show('addSpoke',hub);
 $('topologyScope').textContent=hub?'All approved sites and their current connection state.':'Only this Spoke and its Hub are visible here.';
 const peers=(s.peers||[]).filter(p=>p.role==='spoke');options('removePeer',peers.map(p=>[p.node,p.label]));$('remove').disabled=!peers.length;
 if(s.policy&&!$('policy').contains(document.activeElement)){$('internet').checked=s.policy.internet;$('spokeAccess').checked=s.policy.spoke_access}
 if(s.lan&&!$('lanForm').contains(document.activeElement))for(const[k,v]of Object.entries(s.lan)){const e=$('lanForm').elements[k];if(e)e.type==='checkbox'?e.checked=v:e.value=v}
 if(tab==='wizard')renderWizard();
 const status=s.status||{};
 $('connectedRate').textContent=(status.established_count||0)+' / '+(status.total_count||0);
 $('connectionSummary').textContent=(s.enabled?'Activated':'Disabled')+' · '+(status.state||'Waiting for peer files').replaceAll('_',' ')+(s.lan_reapproval_required?' · New Hub approval required after LAN change':'');
 $('connections').replaceChildren();
 for(const t of status.tunnels||[]){const rate=peerRates.get(String(t.id));card($('connections'),t.peer_label||t.peer,'Tunnel '+(t.tunnel||'unknown')+' · BGP '+(t.bgp||'unknown')+(rate?'\n↓ '+rate[0].toFixed(3)+' / ↑ '+rate[1].toFixed(3)+' Mbit/s':''))}
 if(s.topology)diagram(s);
}
function renderWizard(){
 const hub=state.role==='hub',step=currentStep(),complete=state.workflow.complete;
 const steps=state.workflow.steps,index=steps.indexOf(step);
 if(lastStep!==step){lastStep=step;window.scrollTo({top:0,behavior:'instant'})}
 $('steps').replaceChildren();
 for(const[key,label]of steps.map(k=>[k,labels[k]])){const li=document.createElement('li'),n=steps.indexOf(key);li.className=n===index?'active':n<index?'done':'';if(n===index)li.setAttribute('aria-current','step');const count=document.createElement('span');count.textContent=n<index?'✓':String(n+1);li.append(count,document.createTextNode(label));$('steps').append(li)}
 $('stepCounter').textContent=complete?'TRUSTED FILE EXCHANGE':'STEP '+(index+1)+' OF '+steps.length;
 for(const name of ['profile','import','export','activate'])show(name+'Block',false);
 show('newInvitation',complete&&hub&&step==='request');show('exchangeRequest',complete&&!hub&&step==='approval');show('exchangeApproval',complete&&!hub&&step==='request');
 $('nextHint').textContent='';
 if(step==='profile'){
  show('profileBlock',true);show('hubSetup',hub);show('transportHint',!hub);
  $('stepTitle').textContent=hub?'Create your Hub':'Give this site a name';
  $('stepDescription').textContent=hub?'Choose the connection your trusted Spokes will use, and how you want to share it.':'Your Hub invitation is verified. Choose a name the Hub administrator will recognise.';
  $('create').textContent=hub?'Create Hub →':'Create Spoke →';$('create').disabled=!hub&&!invitationAccepted;
  $('nextHint').textContent=hub?'Next: download an invitation and share it with your trusted Spokes.':'Next: download your request and send it to the Hub owner.';
 }else if((hub&&step==='invitation')||(!hub&&step==='request')||(hub&&step==='approval')){
  show('exportBlock',true);
  const suffix=hub?(step==='invitation'?'invitation':'approved'):'request';
  let recipient=state.workflow.recipient;const peer=(state.peers||[]).find(p=>p.node===recipient);
  options('recipient',[[recipient||'',peer?peer.label+' — approval':hub?'Hub invitation':'Spoke request']]);
  $('stepTitle').textContent=suffix==='invitation'?'Download your Hub invitation':suffix==='request'?'Download your Spoke request':'Download the Spoke approval';
  $('stepDescription').textContent=suffix==='invitation'?'Send this invitation to each trusted Spoke owner. They will use it to create their own request.':suffix==='request'?'Send your request to the Hub owner. They must approve it before you can connect.':'This approval belongs to '+(peer?.label||'the selected Spoke')+' only. Return it to that Spoke owner.';
  $('download').textContent='Download '+(suffix==='approved'?'approval':suffix)+' →';
  $('nextHint').textContent=hub&&step==='approval'?(complete?'After download, return to Monitor. The new Spoke can import its approval and activate.':'Next: activate the Hub. Your Spoke can connect after importing this approval.'):'After download, the wizard will wait for the file returned by the other owner.';
 }else if(step==='activate'){
  show('activateBlock',true);$('stepTitle').textContent='You’re ready to connect';$('stepDescription').textContent='Activate this appliance, then follow the live tunnel and BGP status in Monitor.';
 }else{
  show('importBlock',true);const invitation=!state.configured;
  $('stepTitle').textContent=invitation?'Import your Hub invitation':hub?'Waiting for a Spoke request':'Import your Hub approval';
  $('uploadLabel').textContent=invitation?'Choose the Hub invitation JSON':hub?'Choose a Spoke request JSON':'Choose this Spoke’s approval JSON';
  $('stepDescription').textContent=invitation?'Ask the Hub owner for an invitation. Upload it here, unlock it if encrypted, and verify the sender.':hub?'Your invitation is ready to share. Ask a Spoke owner to return their request, then upload it here. Existing connections remain active.':'Your request has been downloaded. Send it to the Hub owner, then upload the recipient-specific approval they return.';
  $('import').textContent=invitation?'Trust this Hub and continue →':hub?'Approve this Spoke →':'Import approval →';$('import').disabled=!peerFile||!$('trust').checked;
 }
}
async function poll(){if(busy||polling)return;polling=true;try{const before=state?.workflow.complete;state=await api('state');show('login',false);show('workspace',true);show('navigation',true);show('logout',true);if(before===undefined)tab=state.workflow.complete?'monitor':'wizard';if(state.configured)traffic(state);render()}catch(e){note(e.message)}finally{polling=false}}
async function act(name,value={},finish=false){
 busy=true;document.querySelectorAll('main button').forEach(b=>b.disabled=true);note('Applying locally…');
 try{const result=await api(name,value);if(finish){await api('finish',{});tab='monitor'}note(result.lan_reapproval_required?'LAN changed: use Exchange files to request a new Hub approval.':'Saved locally.');return true}catch(e){note(e.message);return false}
 finally{busy=false;document.querySelectorAll('main button').forEach(b=>b.disabled=false);await poll()}
}
$('loginForm').onsubmit=async e=>{e.preventDefault();try{await api('login',Object.fromEntries(new FormData(e.target)));e.target.elements.password.value='';state=null;note('');await poll()}catch(e){note(e.message)}};
$('logout').onclick=async()=>{await api('logout',{});location.reload()};document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>navigate(b.dataset.tab));$('check').onclick=poll;
async function unlockFile(){const d=$('unlockDialog');$('importPassword').value='';d.returnValue='';d.showModal();return new Promise((resolve,reject)=>{d.onclose=()=>{const value=$('importPassword').value;$('importPassword').value='';d.returnValue==='unlock'?resolve(value):reject(Error('Import cancelled'))}})}
$('upload').onchange=async()=>{
 peerFile=null;show('peerReview',false);$('import').disabled=true;const f=$('upload').files[0];if(!f)return;
 try{if(f.size>524288)throw Error('File too large');const file=JSON.parse(await f.text());peerPass=file.format==='sealed-exchange'?await unlockFile():'';const r=await api('inspect',{file,passphrase:peerPass});
  if(!state.configured&&(r.peer.role!=='hub'||r.peer.recipient))throw Error('Choose a Hub invitation, not a Spoke approval.');
  if(state.configured&&state.role==='hub'&&r.peer.role!=='spoke')throw Error('The Hub expects a Spoke request.');
  peerFile=file;$('peerIdentity').textContent=r.peer.label+' ('+r.peer.role+')\nEndpoint: '+(r.peer.endpoint||'Outbound / NAT')+'\nFingerprint: '+r.peer.fingerprint;$('trust').checked=false;show('peerReview',true);
  if(!state.configured&&r.peer.transport){$('setupForm').elements.transport.value=r.peer.transport;$('setupForm').elements.transport.disabled=true}note('Verify the intended sender, then confirm below.');
 }catch(e){note(e.message)}
};
$('trust').onchange=()=>{$('import').disabled=!peerFile||!$('trust').checked};
$('import').onclick=async()=>{
 if(!$('trust').checked||!peerFile)return;
 if(!state.configured){invitationAccepted=true;note('Hub invitation trusted. Continue with this Spoke’s site details.');render();return}
 const ok=await act('import',{file:peerFile,passphrase:peerPass,trusted:true});if(ok){peerFile=null;peerPass='';$('upload').value='';show('peerReview',false);if(state.workflow.complete&&state.role==='spoke')navigate('monitor');else{exchangeStep=null;render()}}
};
$('setupForm').onsubmit=e=>{e.preventDefault();const f=e.target,v={label:f.elements.label.value.trim(),transport:f.elements.transport.value,endpoint:f.elements.endpoint.value.trim(),internet_gateway:f.elements.internet_gateway.checked,isolate_spokes:f.elements.isolate_spokes.checked};if(state.role==='spoke')Object.assign(v,{file:peerFile,passphrase:peerPass,trusted:invitationAccepted});act('initialize',v)};
$('encrypt').onchange=()=>show('passphrases',$('encrypt').checked);
$('download').onclick=async()=>{
 const step=currentStep(),wasComplete=state.workflow.complete;
 try{const r=await api('export',{recipient:$('recipient').value||null,encrypt:$('encrypt').checked,passphrase:$('exportPassword').value,confirm:$('exportConfirm').value});const url=URL.createObjectURL(new Blob([JSON.stringify(r.file,null,2)],{type:'application/json'})),a=document.createElement('a');a.href=url;a.download=r.filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);$('exportPassword').value='';$('exportConfirm').value='';peerFile=null;peerPass='';show('peerReview',false);$('upload').value='';exchangeStep=wasComplete&&state.role==='spoke'?'approval':null;if(wasComplete&&state.role==='hub'&&step==='approval')tab='monitor';note('Downloaded '+r.filename+'. Share it with the intended owner.');await poll()}catch(e){note(e.message)}
};
$('finishSetup').onclick=()=>act('apply',{},true);
$('newInvitation').onclick=()=>{exchangeStep='invitation';render()};$('exchangeRequest').onclick=()=>{exchangeStep='request';render()};$('exchangeApproval').onclick=()=>{exchangeStep='approval';render()};
$('addSpoke').onclick=()=>navigate('wizard');$('topologyButton').onclick=()=>navigate('topology');
document.querySelectorAll('[data-action]').forEach(b=>b.onclick=()=>{if(b.dataset.action==='disable'&&!confirm('Disable this appliance connection?'))return;act(b.dataset.action)});
$('applyPolicy').onclick=()=>act('policy',{internet:$('internet').checked,spoke_access:$('spokeAccess').checked});$('remove').onclick=()=>{if(confirm('Remove this Spoke and revoke its approval?'))act('remove',{node:$('removePeer').value})};
$('lanForm').onsubmit=e=>{e.preventDefault();const f=e.target;if(!confirm('Apply LAN settings? A subnet change requires new Hub approval.'))return;act('lan',{address:f.elements.address.value,dhcp:f.elements.dhcp.checked,pool_start:f.elements.pool_start.value,pool_end:f.elements.pool_end.value,lease_hours:Number(f.elements.lease_hours.value)})};
const seriesColors = ['#61afff', '#62dba6', '#ffc779', '#c9a4ff', '#ff92aa', '#67d9df'];

function traffic(s) {
 const now = s.sample_time || Date.now() / 1000;
 const history = s.history || [];
 const tunnels = s.status?.tunnels || [];
 const recent = history.at(-1);
 peerRates = new Map(recent && now - recent[0] < 15 ? Object.entries(recent[1]) : []);
 const totals = Array.from(peerRates.values()).reduce(([rx,tx], [r,t]) => [rx+r,tx+t], [0,0]);
 for (const [i, id, label] of [[0,'downloadRate','Download'],[1,'uploadRate','Upload']]) {
  $(id).textContent = label + (peerRates.size ? ' ' + totals[i].toFixed(3) + ' Mbit/s' : ' —');
 }
 const hub = s.role === 'hub';
 const series = [{id:'total',label:hub?'Hub total':tunnels[0]?.peer_label||'Hub link'}];
 if (hub) for (const tunnel of tunnels) series.push({id:String(tunnel.id),label:tunnel.peer_label||tunnel.peer});
 const legend = $('trafficLegend');
 const signature = JSON.stringify(series);
 if (legend.dataset.series !== signature) {
  legend.dataset.series = signature;
  legend.replaceChildren();
  series.forEach(({id,label}, i) => {
   const button = document.createElement('button');
   button.type = 'button';
   button.className = 'seriesButton quiet series' + i % seriesColors.length;
   button.textContent = label;
   button.setAttribute('aria-pressed', String(!hiddenSeries.has(id)));
   button.onclick = () => {
    if (hiddenSeries.has(id)) hiddenSeries.delete(id);
    else hiddenSeries.add(id);
    button.setAttribute('aria-pressed', String(!hiddenSeries.has(id)));
    traffic(state);
   };
   legend.append(button);
  });
 }
 const direction = $('trafficDirection').value;
 const axes = direction === 'both' ? [0,1] : [Number(direction)];
 const lines = series.flatMap(({id},i) => hiddenSeries.has(id) ? [] : axes.map(axis => ({
  color:seriesColors[i % seriesColors.length], axis,
  values:history.map(([time, rows]) => {
   if (id !== 'total') return [time, rows[id]?.[axis]];
   const rates = Object.values(rows);
   return [time, rates.length ? rates.reduce((sum,pair) => sum + pair[axis], 0) : undefined];
  })
 })));
 const canvas = $('traffic'), ctx = canvas.getContext('2d');
 const left = 70, right = canvas.width - 18, top = 18, bottom = canvas.height - 32;
 const peak = lines.reduce((max,line) => line.values.reduce((m,[,rate]) => Math.max(m,rate||0),max), 0.01);
 ctx.clearRect(0,0,canvas.width,canvas.height);
 ctx.font = '14px system-ui';
 ctx.fillStyle = '#a5b7cb';
 ctx.strokeStyle = '#2c3f58';
 ctx.lineWidth = 1;
 ctx.setLineDash([]);
 for (let i=0; i<=4; i++) {
  const y = bottom - (bottom-top)*i/4;
  ctx.beginPath();ctx.moveTo(left,y);ctx.lineTo(right,y);ctx.stroke();
  ctx.fillText((peak*i/4).toPrecision(2), 8, y+4);
 }
 for (const [i,label] of ['60m ago','45m','30m','15m','Now'].entries()) {
  ctx.fillText(label, left+(right-left)*i/4-(i===4?26:0), bottom+23);
 }
 for (const line of lines) {
  ctx.beginPath();
  ctx.strokeStyle = line.color;
  ctx.lineWidth = 2;
  ctx.setLineDash(line.axis ? [6,4] : []);
  let last;
  for (const [time,rate] of line.values) {
   if (rate === undefined || time < now-3600 || time > now+5) {last=undefined;continue}
   const x = left + (right-left)*Math.min(1,(time-now+3600)/3600);
   const y = bottom - (bottom-top)*rate/peak;
   if (last !== undefined && time-last <= 15 && time>last) ctx.lineTo(x,y);
   else ctx.moveTo(x,y);
   last=time;
  }
  ctx.stroke();
 }
 show('trafficWaiting', !history.some(([,rows]) => Object.keys(rows).length));
}
$('trafficDirection').onchange = () => {if (state) traffic(state)};

function svg(tag, attrs) {
 const node = document.createElementNS('http://www.w3.org/2000/svg',tag);
 for (const [key,value] of Object.entries(attrs)) node.setAttribute(key,value);
 return node;
}

const topologyIcons = {
 internet:'M2 12a10 10 0 1 0 20 0 10 10 0 1 0-20 0 M2 12h20 M12 2c-6 6-6 14 0 20 6-6 6-14 0-20',
 hub:'M4 5h16v5H4z M4 14h16v5H4z M7 7.5h1 M7 16.5h1 M12 10v4',
 spoke:'M4 8l8-5 8 5v12H4z M9 20v-6h6v6 M9 9h6',
 lan:'M8 3h8v6H8z M3 15h7v6H3z M14 15h7v6h-7z M12 9v3 M6 15v-3h12v3'
};

function topologyNode(kind, label, detail, status) {
 const card = document.createElement('article');
 card.className = 'topologyNode ' + kind;
 const icon = svg('svg',{viewBox:'0 0 24 24','aria-hidden':'true'});
 icon.append(svg('path',{d:topologyIcons[kind],fill:'none',stroke:'currentColor','stroke-width':'1.6','stroke-linecap':'round','stroke-linejoin':'round'}));
 const header = document.createElement('div');
 const title = document.createElement('strong');
 title.textContent = label;
 const eyebrow = document.createElement('span');
 eyebrow.className = 'topologyRole';
 eyebrow.textContent = {hub:'Hub',spoke:'Spoke',internet:'Uplink',lan:'Local network'}[kind];
 header.append(eyebrow,title);
 card.append(icon,header);
 const text = document.createElement('p');
 text.textContent = detail;
 card.append(text);
 if (status) {
  const badge = document.createElement('span');
  badge.className = 'linkState ' + (status.up ? 'live' : 'offline');
  badge.textContent = status.label;
  card.append(badge);
 }
 return card;
}

function diagram(s) {
 const data = s.topology;
 const hub = data?.sites.find(site => site.role === 'hub');
 if (!hub) {$('diagram').replaceChildren();return}
 const visibleSpokes = data.sites.filter(site => site.role === 'spoke' &&
  (s.role === 'hub' || site.id === data.local));
 const diagram = document.createElement('div');
 diagram.className = 'networkMap';
 const uplink = topologyNode('internet','Open Internet',
  hub.egress ? 'Dedicated WAN · '+hub.egress : 'Shared WAN · '+hub.wan,
  s.policy ? {up:s.policy.internet,label:s.policy.internet?'Sharing enabled':'Sharing off'} : null);
 const hubNode = topologyNode('hub',hub.label,
  [hub.endpoint||'Endpoint unavailable',...(hub.prefixes.length ? hub.prefixes : ['LAN unused'])].join(' · '));
 const backbone = document.createElement('div');
 backbone.className = 'topologyBackbone';
 backbone.append(uplink,hubNode);
 diagram.append(backbone);
 const branches = document.createElement('div');
 branches.className = 'topologyBranches';
 for (const site of visibleSpokes) {
  const peer = s.role === 'hub' ? site.peer : hub.peer;
  const tunnel = (s.status?.tunnels||[]).find(row => row.peer === peer);
  const up = tunnel?.tunnel === 'established' && tunnel?.bgp === 'Established';
  const branch = document.createElement('div');
  branch.className = 'topologyBranch ' + (up?'live':'offline');
  branch.append(topologyNode('spoke',site.label,site.endpoint||'Outbound / NAT',
   {up,label:up?'Connected':'Disconnected / connecting'}));
  branch.append(topologyNode('lan','LAN',site.prefixes.join(' · ')||'No prefixes'));
  branches.append(branch);
 }
 diagram.append(branches);
 $('diagram').replaceChildren(diagram);
}
