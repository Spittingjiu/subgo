const q=s=>document.querySelector(s);
let sources=[], allNodes=[], modalAllNodes=[], sourceViewId='all', editingSubId=null;
const nodeMetadata = new Map(), selectedNodeIds = new Set(), selectedNodeMetadata = new Map();
let nodePage=1, modalPage=1, nodeViewVersion=0, nodeBusy=false, subSession=0, subReview=null;
let subOriginal={name:'',hashes:[],autoPrune:false}, subModalLoading=false, linkActionVersion=0;
let subscriptionsRequestVersion=0;
let subscriptionsVersion=0, currentLinkReport=null, currentLinkSubscriptionId=null, authenticated=false;
const nodePendingIds=new Set();
const isEnabled=value=>value===true||value===1||value==='1';
const healthKey=n=>{const s=String(n.connectivity_status||'unknown').toLowerCase();return ['fail','failed','disconnected','unreachable','error'].includes(s)?'fail':s==='ok'?'ok':s==='testing'?'testing':'unknown';};
const healthLabel=n=>({ok:'可用',fail:'不可用',testing:'检测中',unknown:'未检测'})[healthKey(n)];
function cacheNodes(rows){for(const n of rows){const id=nodeRealId(n);if(id)nodeMetadata.set(id,n);}}
function protocolOf(n){return String(n.protocol||String(n.raw_link||'').split(':')[0]||'unknown').toLowerCase();}
function nodeSearchText(n){return [n.node_name,protocolOf(n),n.source_name,n.source_id,n.display_id,healthLabel(n),isEnabled(n.enabled)?'启用 enabled':'禁用 disabled'].join(' ').toLowerCase();}
function matchesSearch(n,text){return String(text||'').toLowerCase().trim().split(/\s+/).filter(Boolean).every(word=>nodeSearchText(n).includes(word));}
function fillProtocols(selector,nodes){const el=q(selector);if(!el)return;const old=el.value;const values=[...new Set(nodes.map(protocolOf))].sort();el.innerHTML='<option value="">全部协议</option>'+values.map(v=>`<option value="${esc(v)}">${esc(v.toUpperCase())}</option>`).join('');if(values.includes(old))el.value=old;}

let currentModalLinks={general:'',clash:''};
let currentModalClashImports={general:'',clash:''};
let currentModalGeneralImports={general:{v2rayn:'',v2rayng:''},clash:{v2rayn:'',v2rayng:''}};
let currentLinkTab='general';
let theme='dark';
let activeTab='home';
const selectedNodeHashes=new Set();
let cfFilterSourceId=null;
let cfFilterDraft={};
// per-subscription persisted filter snapshots
// 结构：{ [subId|'new']: { [sourceId]: { transport:Set, hostType:Set, alpn:Set, tag:Set } } }
let subFilterState={};
const esc=(s)=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
function normalizeNodeView(n){const real=Number(n.real_id??n.id??0);const disp=String(n.display_id||n.display_no||String(real).padStart(3,'0'));return {...n,id:real,real_id:real,display_id:disp};}
function nodeRealId(n){const id=Number(n?.real_id??n?.id??0);return Number.isSafeInteger(id)&&id>0?id:0;} 

const isLocalSource=(s)=>String(s?.source_type||'sui_api')==='local' || String(s?.panel_url||'')==='local://manual';
const orderedSources=()=>[...sources].sort((a,b)=>{
  const al=isLocalSource(a), bl=isLocalSource(b);
  if(al!==bl) return al?-1:1;
  return Number(a.id||0)-Number(b.id||0);
});
const toast=(t,c='')=>UI.toast(t,c);
const api=(url,opt={})=>UI.api(url,opt);
function setAuthMode(v){document.body.classList.toggle('auth-mode',v)}
function updateThemeButton(){
  const btn=q('#themeBtn');
  if(!btn) return;
  btn.textContent = theme === 'light' ? '深色主题' : '黑色主题';
}
function applyTheme(next='dark'){
  theme = (next === 'light') ? 'light' : 'dark';
  document.body.classList.toggle('theme-light', theme === 'light');
  updateThemeButton();
  try{ localStorage.setItem('sui_sub_theme', theme); }catch(_e){}
}
function toggleTheme(){
  applyTheme(theme === 'light' ? 'dark' : 'light');
}

function switchTab(tab){
  if(!['home','nodes','sui','user'].includes(tab))tab='home';activeTab=tab;
  try{localStorage.setItem('sui_sub_last_tab',tab);}catch(_error){}
  for(const [name,id,nav,bottom] of [['home','tab-home','tabHomeBtn','bnHome'],['nodes','tab-nodes','tabNodeBtn','bnNodes'],['sui','tab-sui','tabSuiBtn','bnSui'],['user','tab-user','tabUserBtn','bnUser']]){
    q('#'+id).classList.toggle('hide',name!==tab);q('#'+nav).classList.toggle('tab-on',name===tab);q('#'+bottom).classList.toggle('bnav-on',name===tab);
  }
  if(authenticated&&Date.now()-lastTasksAt>30000)loadTasks(false).catch(UI.reportError);
  if(authenticated){if(tab==='sui')loadSuiNodes().catch(UI.reportError);if(tab==='user')loadAdminUser().catch(UI.reportError);}
}
function showLogin(message=''){
  authenticated=false;UI.invalidateAll();UI.closeAll();++subSession;++linkActionVersion;
  stopTaskPolling();clearInterval(logsTimer);logsTimer=0;q('#loginCard').classList.remove('hide');q('#app').classList.add('hide');setAuthMode(true);q('#lmsg').textContent=message;
  currentModalLinks={general:'',clash:''};currentLinkReport=null;subReview=null;nodeBusy=false;subModalLoading=false;taskState=[];taskRecent={};taskCancelPending.clear();taskDetailCache.clear();
  if(message)q('#lu').focus();
}
async function checkAuth(){
  const request=UI.request('auth');
  try{await api('/api/auth/me',{signal:request.signal});if(!request.current())return;
    authenticated=true;q('#loginCard').classList.add('hide');q('#app').classList.remove('hide');setAuthMode(false);await init();
  }catch(error){if(error.status!==401&&request.current()){showLogin('无法检查登录状态，请重试登录');UI.reportError(error);}}
}
let loginPending=false;
async function login(){
  if(loginPending)return;loginPending=true;UI.setError('#lmsg','');
  try{await api('/api/auth/login',{method:'POST',body:JSON.stringify({username:q('#lu').value.trim(),password:q('#lp').value})});q('#lp').value='';await checkAuth();}
  catch(error){q('#lmsg').textContent=UI.safeText(error.message);}
  finally{loginPending=false;}
}
async function logout(){try{await api('/api/auth/logout',{method:'POST',body:'{}'});}finally{showLogin('已退出登录');}}

let addSourceType='sui',addSourceSession=0;
function openAddSourceModal(){
  setAddSourceType(addSourceType||'sui');
  ++addSourceSession;UI.setError('#addSourceError','');UI.openModal('addSourceModal','#sourceNameInput');
}
function closeAddSourceModal(){++addSourceSession;UI.invalidate('source-save');UI.closeModal('addSourceModal');q('#sourceTokenInput').type='password';q('#sourceSecretVisible').checked=false;}
function setAddSourceType(kind){
  addSourceType=kind;
  const cfg={
    sui:{name:'名称（例如：东京）',panel:'面板地址（https://panel.example.com）',token:'SUI API Token（或填账号:密码，会自动换 token）',hint:'连接 SUI / SUI-Go 面板，账号密码只用于换永久 token。'},
    sbui:{name:'名称（例如：SBUI-本地）',panel:'SBUI 地址（https://sbui.example.com）',token:'API Token（或填 用户名:密码，会自动换 token）',hint:'连接 SBUI/S-Matrix /api/v1/sub/default。'},
    xui:{name:'名称（例如：3x-ui-主面板）',panel:'3x-ui 面板地址（https://panel.example.com/随机路径）',token:'API Token 或 用户名:密码',hint:'连接 MHSanaei/3x-ui，自动登录读取入站客户端 subId 并同步订阅节点。'}
  }[kind]||{};
  q('#sourceNameInput').placeholder=cfg.name||'名称';
  q('#sourcePanelInput').placeholder=cfg.panel||'面板地址或订阅链接';
  q('#sourceTokenInput').placeholder=cfg.token||'API Token 或账号:密码';
  q('#addSourceHint').textContent=cfg.hint||'';
  [['sui','addTypeSui'],['sbui','addTypeSbui'],['xui','addTypeXui']].forEach(([k,id])=>q('#'+id)?.classList.toggle('bnav-on',k===kind));
}
function saveAddSourceModal(){return addSource(addSourceType||'sui')}
async function addSource(kind='sui'){
  const session=addSourceSession,request=UI.request('source-save',{session});
  try{
    const k=String(kind||'sui').toLowerCase();
    const name=q('#sourceNameInput').value.trim();
    const panel_url=q('#sourcePanelInput').value.trim();
    const panel_token=q('#sourceTokenInput').value.trim();
    const source_type=k==='sbui'?'sbui':(k==='xui'?'xui':'sui_api');
    await api('/api/sources',{method:'POST',signal:request.signal,body:JSON.stringify({name,panel_url,panel_token,source_type})});
    if(!request.current())return;
    if(session===addSourceSession){q('#sourceNameInput').value='';q('#sourcePanelInput').value='';q('#sourceTokenInput').value='';closeAddSourceModal();}
    toast('连接源已保存；自动同步的真实状态请查看后台任务','ok');
    await refreshAll();
  }catch(e){if(request.current()&&session===addSourceSession){UI.setError('#addSourceError',e.message);UI.reportError(e);}}
}
function toggleSourceSecret(visible){q('#sourceTokenInput').type=visible?'text':'password';}


async function editSourceName(id){
  const oldName=(sources.find(x=>Number(x.id)===Number(id))||{}).name||'';
  const name=(prompt('请输入新的源名称：',oldName)||'').trim();
  if(!name || name===oldName) return;
  await api('/api/sources/'+id,{method:'PUT',body:JSON.stringify({name})});
  toast('源名称已更新','ok');
  await refreshAll();
}
async function toggleSourceEnabled(id){
  const s=(sources||[]).find(x=>Number(x.id)===Number(id));
  if(!s) return;
  const next=Number(s.enabled??1)?0:1;
  await api('/api/sources/'+id,{method:'PUT',body:JSON.stringify({enabled:next})});
  toast(next?'源已启用':'源已停用','ok');
  await refreshAll();
  await loadNodes();
}
async function deleteSource(id){if(!confirm('确认删除该源？'))return;await api('/api/sources/'+id,{method:'DELETE'});await refreshAll();}

function simplifySourceSyncStatus(raw=''){
  const t=String(raw||'').trim();
  if(!t) return '未同步';
  const l=t.toLowerCase();
  if(l==='ok') return '同步成功';
  if(l==='pending') return '等待同步';
  if(l==='local') return '本地源';

  // 常见错误归一成简洁中文
  if(/etimedout|connect timeout|timeout/.test(l)) return '连接超时，请检查面板地址/网络';
  if(/econnrefused/.test(l)) return '连接被拒绝，请检查端口/服务是否启动';
  if(/enotfound|getaddrinfo/.test(l)) return '域名解析失败，请检查域名配置';
  if(/self[- ]signed|certificate|tls/.test(l)) return '证书或TLS握手异常';
  if(/http\s*401|unauthorized/.test(l)) return '鉴权失败（Token无效或已过期）';
  if(/http\s*403|forbidden/.test(l)) return '无权限访问该面板';
  if(/http\s*404/.test(l)) return '接口地址不存在（404）';
  if(/http\s*5\d\d/.test(l)) return '面板服务异常（5xx）';
  if(/fetch failed|socket hang up|ehostunreach|enetunreach/.test(l)) return '网络不可达，请检查服务器连通性';

  if(l.startsWith('error:')) return '同步失败，请检查源配置';
  return t.length>42?`${t.slice(0,42)}…`:t;
}

function sourceSyncText(s){
  if(isLocalSource(s)) return '';
  if(!s.last_sync_at) return '未同步';
  return `${simplifySourceSyncStatus(s.last_sync_status||'')} · ${new Date(s.last_sync_at).toLocaleString()}`;
}
function isCfSource(s){
  const type=String(s?.source_type||'').toLowerCase();
  if(type.includes('cf') || type.includes('cloudflare')) return true;
  const panel=String(s?.panel_url||'').toLowerCase();
  const name=String(s?.name||'').toLowerCase();
  return /(workers\.dev|cloudflare)/.test(panel) || /(^|[^a-z])cf([^a-z]|$)|cloudflare/.test(name);
}
function sourceFlavorLabel(s){
  const type=String(s?.source_type||'').toLowerCase();
  if(type==='sbui') return 'SBUI';
  if(type==='xui' || type==='3x_ui') return '3x-ui';
  if(type!=='sui_api') return '';
  const f=String(s?.sui_flavor||'unknown').toLowerCase();
  if(f==='go') return 'SUI-GO';
  if(f==='node') return 'SUI-NODE';
  return 'SUI-未知';
}
function renderSourceCard(source){
  const local=isLocalSource(source),enabled=isEnabled(source.enabled??true),id=Number(source.id),flavor=sourceFlavorLabel(source);
  const button=(action,label)=>`<button data-source-action="${action}" data-source-id="${id}">${label}</button>`;
  return `<div class="src-item" style="opacity:${enabled?1:.65}"><div class="row" style="justify-content:space-between"><div><b>${esc(source.name||'')}</b> ${flavor?'<span class="pill">'+esc(flavor)+'</span>':''}<div class="muted">${esc(source.panel_url||'')}</div><div class="muted">节点数：${Number(source.node_count||0)}</div></div><div class="row">${local?'':`<span class="${enabled?'ok':'err'}">${enabled?'已启用':'已停用'}</span><span class="pill">${esc(sourceSyncText(source))}</span>`}${button('focus','看节点')}${local?'':button('panel','安全访问（独立 origin）')+button('toggle',enabled?'停用':'启用')+button('rename','改名')+button('delete','删除')}</div></div></div>`;
}
function renderSourceGroup(title, list, open=true){
  return `<details ${open?'open':''} style="border:1px solid var(--line);border-radius:12px;padding:8px 10px;background:var(--bg2);margin-top:8px"><summary style="cursor:pointer;user-select:none;font-weight:700">${title}（${list.length}）</summary><div style="margin-top:8px">${list.length?list.map(renderSourceCard).join(''):'<div class="muted">暂无</div>'}</div></details>`;
}
function isSbuiSource(s){return String(s?.source_type||'').toLowerCase()==='sbui';}
function isXuiSource(s){const t=String(s?.source_type||'').toLowerCase();return t==='xui'||t==='3x_ui';}
function renderSourcesUI(){
  const box=q('#sources');
  if(!sources.length){box.innerHTML='<div class="muted">暂无</div>';loadSuiSourceOptions(); renderNodeSourceSelect(); renderModalSourceFilter(); return;}
  const ordered=orderedSources();
  const sbuiSources=ordered.filter(s=>isSbuiSource(s));
  const xuiSources=ordered.filter(s=>isXuiSource(s));
  const suiSources=ordered.filter(s=>!isSbuiSource(s)&&!isXuiSource(s));
  box.innerHTML=`${renderSourceGroup('SUI源',suiSources,false)}${renderSourceGroup('SBUI源',sbuiSources,false)}${renderSourceGroup('3x-ui源',xuiSources,false)}`;
  loadSuiSourceOptions(); renderNodeSourceSelect(); renderModalSourceFilter();
}
async function focusSource(id){switchTab('nodes');return setNodeSource(String(id));}
async function openSecurePanel(id){
  const sourceId=Number(id);if(!Number.isSafeInteger(sourceId)||sourceId<=0)return;
  // Reserve a user-initiated window before awaiting the one-time launch ticket.
  const popup=window.open('about:blank','_blank');if(popup)popup.opener=null;
  try{
    const result=await api('/api/panel-proxy/ticket',{method:'POST',body:JSON.stringify({source_id:sourceId})});
    const url=new URL(result.url,location.origin);
    if(url.origin===location.origin||url.protocol!=='https:'||url.username||url.password)throw new Error('面板代理未配置独立 HTTPS origin，已阻止同源上游页面');
    if(popup){popup.location.replace(url.href);}
    else{
      toast('弹窗被浏览器拦截，点击通知中的“打开独立面板”继续');
      const link=document.createElement('a');link.textContent=' 打开独立面板';link.href=url.href;link.target='_blank';link.rel='noopener noreferrer';link.referrerPolicy='no-referrer';q('#toastText').appendChild(link);
    }
  }catch(error){popup?.close();throw error;}
}

function parseNodeMeta(n){
  const raw=String(n?.raw_link||'').trim();
  const name=String(n?.node_name||'');
  let transport='other', hostType='domain', host='', alpn='';
  try{
    const u=new URL(raw);
    host=(u.hostname||'').trim();
    // 标准判定：纯 IPv4 / 含冒号即 IPv6 / 其余视为域名
    if(/^\d+\.\d+\.\d+\.\d+$/.test(host)) hostType='ipv4';
    else if(host.includes(':')) hostType='ipv6';
    else hostType='domain';
    transport=(u.searchParams.get('type')||'').toLowerCase()||'other';
    alpn=(u.searchParams.get('alpn')||'').toLowerCase();
  }catch(_e){}
  // 回退保护：避免异常情况下 hostType 误判导致筛选放行
  if(hostType!=='ipv4' && hostType!=='ipv6' && hostType!=='domain') hostType='domain';
  const nn=name.toUpperCase();
  const tags=[];
  if(/移动/.test(name)) tags.push('移动');
  if(/联通/.test(name)) tags.push('联通');
  if(/电信/.test(name)) tags.push('电信');
  if(/HKG/.test(nn)) tags.push('HKG');
  if(/SJC/.test(nn)) tags.push('SJC');
  if(/SIN/.test(nn)) tags.push('SIN');
  if(/NRT/.test(nn)) tags.push('NRT');
  if(/LAX/.test(nn)) tags.push('LAX');
  if(/SEA/.test(nn)) tags.push('SEA');
  if(/MAA/.test(nn)) tags.push('MAA');
  if(/原生地址/.test(name)) tags.push('原生地址');
  return {transport,hostType,host,alpn,tags};
}

function buildCfFilters(nodes){
  const count=(arr,key)=>arr.reduce((m,x)=>{m[x[key]]=(m[x[key]]||0)+1;return m;},{});
  const metas=nodes.map(parseNodeMeta);
  const transports=count(metas,'transport');
  const hostTypes=count(metas,'hostType');
  const alpns={h3:0,h2:0};
  for(const m of metas){ if((m.alpn||'').includes('h3')) alpns.h3++; if((m.alpn||'').includes('h2')) alpns.h2++; }
  const tags=['移动','联通','电信','HKG','SJC','SIN','NRT','LAX','SEA','MAA','原生地址'];
  const tagCounts={};
  for(const t of tags) tagCounts[t]=metas.filter(x=>x.tags.includes(t)).length;
  return {metas,transports,hostTypes,alpns,tagCounts};
}

function optionCheckbox(name,label,count,checked=false){
  return `<label style="display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);padding:6px 10px;border-radius:10px;background:var(--bg2)"><input type="checkbox" data-cf-key="${esc(name)}" ${checked?'checked':''}/> ${label} <span class="muted">(${count})</span></label>`;
}

let cfOwnerSession=null;
async function openCfFilterModal(sourceId){
  const id=Number(sourceId);if(!Number.isSafeInteger(id)||id<=0)return;
  const owner=q('#subModal').classList.contains('hide')?null:subSession;
  cfFilterSourceId=id;cfOwnerSession=owner;
  const request=UI.request('cf-filter',{id,owner}),source=sources.find(s=>Number(s.id)===id);
  q('#cfFilterTitle').textContent='CF 候选筛选 · '+(source?.name||id);q('#cfFilterBody').textContent='正在加载…';UI.setError('#cfFilterError','');UI.openModal('cfFilterModal');
  try{
    const result=await api('/api/view/nodes?sourceId='+id,{signal:request.signal});
    if(!request.current()||id!==cfFilterSourceId||(owner!==null&&owner!==subSession))return;
    const nodes=result.nodes||[],filters=buildCfFilters(nodes),draft=cfFilterDraft[String(id)]||{transport:new Set(),hostType:new Set(),alpn:new Set(),tag:new Set()};
    const section=(title,group,values,counts)=>`<div style="margin:8px 0"><b>${title}</b><div class="row" style="margin-top:6px">${values.map(value=>optionCheckbox(`${group}:${value}`,esc(value.toUpperCase()),Number(counts[value]||0),draft[group]?.has(value))).join('')}</div></div>`;
    q('#cfFilterBody').innerHTML=`<div class="muted">节点 ${nodes.length} 个。仅过滤候选，不删除已选节点。</div>`+section('传输层','transport',['ws','xhttp','other'],filters.transports)+section('地址类型','hostType',['domain','ipv4','ipv6'],filters.hostTypes)+section('ALPN','alpn',['h3','h2'],filters.alpns)+section('标签画像','tag',Object.keys(filters.tagCounts),filters.tagCounts);
  }catch(error){if(request.current()){UI.setError('#cfFilterError',error.message);UI.reportError(error);}}
}
function closeCfFilterModal(){UI.invalidate('cf-filter');UI.closeModal('cfFilterModal');cfFilterSourceId=null;cfOwnerSession=null;}
function clearCfFilterDraft(){document.querySelectorAll('#cfFilterBody input[data-cf-key]').forEach(input=>input.checked=false);}
function applyCfFilter(){
  if(!cfFilterSourceId)return;
  if(cfOwnerSession!==null&&cfOwnerSession!==subSession){closeCfFilterModal();return;}
  const id=String(cfFilterSourceId),next={transport:new Set(),hostType:new Set(),alpn:new Set(),tag:new Set()};
  document.querySelectorAll('#cfFilterBody input[data-cf-key]').forEach(input=>{if(!input.checked)return;const [group,key]=String(input.dataset.cfKey||'').split(':');if(next[group]&&key)next[group].add(key);});
  cfFilterDraft[id]=next;
  if(cfOwnerSession!==null){const key=String(editingSubId||'new');if(!subFilterState[key])subFilterState[key]={};subFilterState[key][id]=Object.fromEntries(Object.entries(next).map(([group,values])=>[group,[...values]]));}
  closeCfFilterModal();nodePage=1;modalPage=1;renderNodes();
  if(!q('#subModal').classList.contains('hide'))renderSubModal();
}

function passCfFilter(node){
  const sid=String(node?.source_id||'');
  const src=(sources||[]).find(s=>String(s.id)===sid);
  // 非 CF 源不应用 CF 筛选
  if(!isCfSource(src||{})) return true;
  const d=cfFilterDraft[sid];
  if(!d) return true;
  const hasAny=[...Object.values(d)].some(s=>s&&s.size>0);
  if(!hasAny) return true;
  const m=parseNodeMeta(node);
  if(d.transport?.size && !d.transport.has(m.transport)) return false;
  if(d.hostType?.size && !d.hostType.has(m.hostType)) return false;
  if(d.alpn?.size){
    const ok=[...d.alpn].some(k=>(m.alpn||'').includes(k));
    if(!ok) return false;
  }
  if(d.tag?.size){
    const ok=[...d.tag].some(k=>m.tags.includes(k));
    if(!ok) return false;
  }
  return true;
}

let kernelInstalled=false;
async function refreshKernelStatus(){
  const request=UI.request('kernel-status');
  try{
    const result=await api('/api/kernel/status',{signal:request.signal});if(!request.current())return;
    kernelInstalled=!!result.installed;q('#kernelBadge').textContent=`Mihomo 测试内核：${kernelInstalled?'已安装':'未安装'}`;q('#kernelToggleBtn').textContent=kernelInstalled?'卸载 Mihomo':'安装 Mihomo';
  }catch(error){if(request.current()){q('#kernelBadge').textContent='Mihomo 测试内核：状态异常';q('#kernelToggleBtn').textContent='重试检测';}}
}
async function toggleKernelInstall(){
  try{
    const btn=q('#kernelToggleBtn'); if(btn) btn.disabled=true;
    if(kernelInstalled){
      await api('/api/kernel/uninstall',{method:'POST',body:'{}'});
      toast('Mihomo 测试内核已卸载','ok');
    }else{
      await api('/api/kernel/install',{method:'POST',body:'{}'});
      toast('Mihomo 测试内核已安装','ok');
    }
  }catch(e){
    const nm=q('#nodeMsg'); if(nm){nm.className='err'; nm.textContent=UI.safeText(e.message);}UI.reportError(e);
  }finally{
    const btn=q('#kernelToggleBtn'); if(btn) btn.disabled=false;
    await refreshKernelStatus();
  }
}

async function loadNodes(){
  const sid=sourceViewId, version=++nodeViewVersion;
  const request=UI.request('nodes',{source:sid,version});
  const box=q('#nodes'), pageY=window.scrollY||0, scrollTop=box?.scrollTop||0;
  nodeBusy=true; box?.setAttribute('aria-busy','true');
  UI.setError('#nodeMsg','正在加载当前源节点…'); renderNodeSelection();
  try{
    const result=await api('/api/view/nodes'+(sid==='all'?'':'?sourceId='+encodeURIComponent(sid)),{signal:request.signal});
    if(!request.current()||sid!==sourceViewId||version!==nodeViewVersion)return;
    allNodes=(result.nodes||[]).map(normalizeNodeView);cacheNodes(allNodes);
    fillProtocols('#nodeProtocol',allNodes); renderNodes();
    if(box)box.scrollTop=scrollTop;
    if(activeTab==='nodes')window.scrollTo(0,pageY);
    UI.setError('#nodeMsg','');
  }catch(error){if(request.current()){UI.setError('#nodeMsg',error.message);UI.reportError(error);}}
  finally{if(request.current()){nodeBusy=false;box?.removeAttribute('aria-busy');renderNodeSelection();}}
}
function getLocalSourceId(){const src=sources.find(isLocalSource);return src?String(src.id):'';}
function setLocalAddVisible(){
  const onLocal=String(sourceViewId)===getLocalSourceId()&&!!getLocalSourceId();
  ['#localNodeLink','#localNodeName','#addLocalBtn'].forEach(sel=>{const el=q(sel);if(el)el.style.display=onLocal?'':'none';});
  const src=sources.find(s=>String(s.id)===sourceViewId);
  q('#nodeCfBtn')?.classList.toggle('hide',sourceViewId==='all'||!isCfSource(src));
  const syncBtn=q('#syncNodesBtn');if(syncBtn)syncBtn.textContent=sourceViewId==='all'?'同步所有启用的非本地源':onLocal?'本地源无需同步':'同步当前源';
}
function renderNodeSourceSelect(){
  const sel=q('#nodeSourceSelect');if(!sel)return;
  const rows=orderedSources().filter(s=>isEnabled(s.enabled??true));
  const total=rows.reduce((sum,s)=>sum+Number(s.node_count||0),0);
  sel.innerHTML=`<option value="all">全部启用源（${total}）</option>`+rows.map(s=>`<option value="${Number(s.id)}">${esc(s.name||'本地节点')}（${Number(s.node_count||0)}）</option>`).join('');
  if(!rows.some(s=>String(s.id)===sourceViewId)&&sourceViewId!=='all')sourceViewId='all';
  sel.value=sourceViewId;setLocalAddVisible();
}
function setNodeSource(value){sourceViewId=String(value);nodePage=1;++nodeViewVersion;renderNodeSourceSelect();renderNodes();return loadNodes();}
function connectivityCell(n){
  const status=healthKey(n);
  if(status==='ok')return `<span class="ok">${n.connectivity_latency_ms!=null?esc(n.connectivity_latency_ms)+' ms':'可用'}</span>`;
  if(status==='testing')return '<span class="pill">检测中</span>';
  if(status==='fail')return '<span class="err">不可用</span>';
  return '<span class="muted">未检测</span>';
}
function currentNodeRows(){
  const search=q('#nodeSearch')?.value||'',protocol=q('#nodeProtocol')?.value||'',health=q('#nodeHealth')?.value||'',enabled=q('#nodeEnabled')?.value||'';
  return allNodes.filter(n=>(sourceViewId==='all'||String(n.source_id)===sourceViewId)&&passCfFilter(n)&&matchesSearch(n,search)&&(!protocol||protocolOf(n)===protocol)&&(!health||healthKey(n)===health)&&(!enabled||isEnabled(n.enabled)===(enabled==='1')));
}
function nodePageSize(){return Math.max(1,Math.min(100,Number(q('#nodePageSize')?.value||25)));}
function nodePageRows(){const rows=currentNodeRows();const size=nodePageSize();nodePage=Math.min(Math.max(1,nodePage),Math.max(1,Math.ceil(rows.length/size)));return rows.slice((nodePage-1)*size,nodePage*size);}
function cfSummary(){const sourceMap=new Map(sources.map(s=>[String(s.id),s.name]));return Object.entries(cfFilterDraft).flatMap(([sid,groups])=>Object.entries(groups).filter(([,values])=>values?.size).map(([group,values])=>`${sourceMap.get(sid)||sid}/${group}: ${[...values].join(',')}`)).join('；');}
function updateNodeFilters(){nodePage=1;renderNodes();}
function resetNodeFilters(){['#nodeSearch','#nodeProtocol','#nodeHealth','#nodeEnabled'].forEach(sel=>{const el=q(sel);if(el)el.value='';});cfFilterDraft={};nodePage=1;renderNodes();}
function changeNodePage(delta){nodePage+=Number(delta)||0;renderNodes();q('#nodes')?.scrollTo?.(0,0);}
function renderNodes(){
  const rows=currentNodeRows(),pageRows=nodePageRows(),size=nodePageSize(),box=q('#nodes');if(!box)return;
  const src=sources.find(s=>String(s.id)===sourceViewId);
  const filters=[q('#nodeSearch')?.value?`搜索：${q('#nodeSearch').value}`:'',q('#nodeProtocol')?.value?`协议：${q('#nodeProtocol').value}`:'',q('#nodeHealth')?.value?`连通性：${q('#nodeHealth').selectedOptions?.[0]?.textContent||q('#nodeHealth').value}`:'',q('#nodeEnabled')?.value?`状态：${q('#nodeEnabled').value==='1'?'启用':'禁用'}`:'',cfSummary()].filter(Boolean);
  q('#nodeFilterSummary').textContent=`当前范围：${sourceViewId==='all'?'全部启用源':src?.name||sourceViewId} · 筛选命中 ${rows.length} 个${filters.length?' · '+filters.join('；'):' · 无附加筛选'}`;
  q('#nodePageInfo').textContent=`第 ${nodePage}/${Math.max(1,Math.ceil(rows.length/size))} 页 · 本页 ${pageRows.length} / 筛选 ${rows.length} 个`;
  q('#nodePrev').disabled=nodePage<=1;q('#nodeNext').disabled=nodePage*size>=rows.length;
  q('#checkNodesBtn').textContent=`测速本页（${pageRows.length} 个，仅启用项）`;
  if(!pageRows.length){box.innerHTML='<div class="muted">当前筛选暂无节点。已选集合不会因此改变。</div>';renderNodeSelection();return;}
  box.innerHTML='<table><thead><tr><th>选</th><th>ID</th><th>来源</th><th>节点名 / 协议</th><th>连通性</th><th>状态</th><th>操作</th></tr></thead><tbody></tbody></table>';
  const body=box.querySelector('tbody');
  for(const n of pageRows){
    const id=nodeRealId(n),tr=document.createElement('tr'),local=n.source_type==='local'||isLocalSource(sources.find(s=>Number(s.id)===Number(n.source_id)));
    tr.innerHTML=`<td><input type="checkbox" data-node-id="${id}" aria-label="选择节点 ${esc(n.node_name||n.display_id)}" ${selectedNodeIds.has(id)?'checked':''} ${!id?'disabled':''}/></td><td data-label="编号" title="真实 ID: ${id}">${esc(n.display_id)}</td><td data-label="来源">${esc(n.source_name||n.source_id)}</td><td data-label="节点">${esc(n.node_name||'未命名')} <span class="pill">${esc(protocolOf(n).toUpperCase())}</span></td><td data-label="连通性">${connectivityCell(n)}</td><td data-label="状态">${isEnabled(n.enabled)?'<span class="ok">启用</span>':'<span class="err">禁用</span>'}</td><td><div class="row"><button data-act="toggle" aria-label="${isEnabled(n.enabled)?'停用':'启用'} ${esc(n.node_name||n.display_id)}">${isEnabled(n.enabled)?'停用':'启用'}</button><button data-act="rename">改名</button>${local?'<button class="ghost" data-act="delete">删除本地</button>':''}</div></td>`;
    tr.querySelector('input').addEventListener('change',event=>{if(event.target.checked)selectedNodeIds.add(id);else selectedNodeIds.delete(id);renderNodeSelection();});
    for(const [action,handler] of Object.entries({toggle:toggleNode,rename:renameNode,delete:deleteLocalNode})){
      const button=tr.querySelector(`[data-act="${action}"]`);if(button)button.addEventListener('click',()=>runAction(button,()=>handler(id)));
    }
    body.appendChild(tr);
  }
  renderNodeSelection();
}
function renderNodeSelection(){
  const count=q('#nodeSelectedCount');if(count)count.textContent=`跨筛选已选 ${selectedNodeIds.size} 个（下方均可移除）`;
  for(const sel of ['#bulkEnableBtn','#bulkDisableBtn']){const el=q(sel);if(el)el.disabled=!selectedNodeIds.size||nodeBusy;}
  const chips=q('#nodeSelectedChips');if(!chips)return;chips.innerHTML='';
  for(const id of selectedNodeIds){
    const n=nodeMetadata.get(id),chip=document.createElement('span');chip.className='chip';
    const name=document.createElement('span');name.className='chip-name';name.textContent=`${n?.source_name||'元数据暂不可用'} · ${n?.node_name||'节点 #'+id}`;
    const remove=document.createElement('button');remove.className='ghost';remove.textContent='×';remove.setAttribute('aria-label','移除已选节点 '+(n?.node_name||id));
    remove.addEventListener('click',()=>{selectedNodeIds.delete(id);renderNodeSelection();});chip.append(name,remove);chips.appendChild(chip);
  }
  document.querySelectorAll('#nodes input[data-node-id]').forEach(el=>{el.checked=selectedNodeIds.has(Number(el.dataset.nodeId));});
}
function selectNodeScope(scope,selected){const rows=scope==='page'?nodePageRows():currentNodeRows();for(const n of rows){const id=nodeRealId(n);if(id){if(selected)selectedNodeIds.add(id);else selectedNodeIds.delete(id);}}renderNodeSelection();}
function clearNodeSelection(){selectedNodeIds.clear();renderNodeSelection();}
async function bulkToggleNodes(enabled){
  if(nodeBusy)return toast('节点正在加载，请稍后操作','err');
  const ids=[...selectedNodeIds];if(!ids.length)return toast('请先明确选择节点','err');
  const labels=ids.map(id=>{const n=nodeMetadata.get(id);return `${n?.source_name||'未知源'} / ${n?.node_name||'#'+id}（真实 ID ${id}）`;});
  if(!confirm(`确认${enabled?'启用':'停用'}跨筛选已选的 ${ids.length} 个节点？\n不是全部节点，也不随筛选自动扩大。\n${labels.slice(0,12).join('\n')}${labels.length>12?'\n…其余 '+(labels.length-12)+' 个已选节点':''}`))return;
  const result=await api('/api/nodes/bulk-toggle',{method:'POST',body:JSON.stringify({node_ids:ids,enabled:!!enabled})});
  for(const id of ids){const n=nodeMetadata.get(id);if(n)n.enabled=!!enabled;}
  toast(`已${enabled?'启用':'停用'} ${Number(result.updated||0)} 个已选节点`,'ok');await loadNodes();renderNodeSelection();
}
let checkingConnectivity=false,syncingNodes=false;
async function checkConnectivity(){
  if(checkingConnectivity||nodeBusy)return;
  const pageRows=nodePageRows();
  const rows=pageRows.filter(n=>isEnabled(n.enabled)&&nodeRealId(n)&&!n.missing_since&&isEnabled(sources.find(s=>Number(s.id)===Number(n.source_id))?.enabled??true));
  const ids=rows.map(nodeRealId);
  if(!ids.length)return toast('本页没有可测试的启用节点；不会扩大到其他页面或源','err');
  if(!confirm(`仅测速当前第 ${nodePage} 页的 ${ids.length} 个启用节点（本页共 ${pageRows.length} 个）。不会测试其他筛选/页面。确认开始？`))return;
  checkingConnectivity=true;
  try{await startTask('connectivity',{node_ids:ids,limit:ids.length});UI.setError('#nodeMsg',`已创建本页 ${ids.length} 个节点的测速任务，可在顶部查看进度或取消。`);}
  finally{checkingConnectivity=false;}
}
async function syncAllNodes(){
  if(syncingNodes)return;
  const scope=sources.filter(s=>isEnabled(s.enabled??true)&&!isLocalSource(s)&&(sourceViewId==='all'||String(s.id)===sourceViewId));
  const ids=scope.map(s=>Number(s.id));
  if(!ids.length)return toast('当前范围没有可同步的启用非本地源，不会扩大范围','err');
  if(!confirm(`同步${sourceViewId==='all'?'全部启用的非本地源':'当前源'}，共 ${ids.length} 个：\n${scope.map(s=>s.name||'#'+s.id).join('、')}\n任务创建后可查看进度或取消。`))return;
  syncingNodes=true;try{await startTask('sync',{source_ids:ids});}finally{syncingNodes=false;}
}
async function toggleNode(id){
  id=Number(id);if(nodePendingIds.has(id))return;
  const n=nodeMetadata.get(id)||allNodes.find(x=>nodeRealId(x)===id);if(!n)throw new Error('节点不在已加载元数据中，请刷新');
  const enabled=!isEnabled(n.enabled);nodePendingIds.add(id);
  try{await api('/api/nodes/'+id+'/toggle',{method:'POST',body:JSON.stringify({enabled})});n.enabled=enabled;toast(`节点已${enabled?'启用':'停用'}`,'ok');await loadNodes();}
  finally{nodePendingIds.delete(id);}
}
async function addLocalNode(){
  const raw=(q('#localNodeLink')?.value||'').trim(),name=(q('#localNodeName')?.value||'').trim();
  if(!raw)return toast('请先粘贴节点链接','err');
  await api('/api/local-nodes',{method:'POST',body:JSON.stringify({raw_link:raw,name})});
  if(q('#localNodeLink')?.value.trim()===raw)q('#localNodeLink').value='';
  if(q('#localNodeName')?.value.trim()===name)q('#localNodeName').value='';
  toast('已添加到本地节点','ok');await refreshAll();await loadNodes();
}
async function renameNode(id){
  const n=nodeMetadata.get(Number(id))||allNodes.find(x=>nodeRealId(x)===Number(id));
  const value=prompt('输入新节点名：',String(n?.node_name||''));if(value===null)return;
  const name=String(value||'').trim();if(!name)return toast('节点名不能为空','err');
  await api('/api/nodes/'+Number(id)+'/rename',{method:'PUT',body:JSON.stringify({name})});toast('节点名已同步更新','ok');await refreshAll();await loadNodes();
}
async function deleteLocalNode(id){
  const n=nodeMetadata.get(Number(id));if(!confirm(`删除本地节点 ${n?.node_name||'#'+id}？订阅中的选择不会被静默扩大。`))return;
  await api('/api/local-nodes/'+Number(id),{method:'DELETE'});selectedNodeIds.delete(Number(id));nodeMetadata.delete(Number(id));toast('本地节点已删除','ok');await refreshAll();await loadNodes();
}

function conversionSummary(report={}){return `输入 ${Number(report.input_count||0)} · 成功 ${Number(report.converted_count||0)} · 跳过 ${Number(report.skipped_count||0)} · ${report.valid===true?'配置有效':'配置无效（invalid）'}`;}
function renderConversionReport(report={}){
  const safe=value=>esc(UI.safeText(value));
  const errors=Array.isArray(report.errors)?report.errors:[],warnings=Array.isArray(report.warnings)?report.warnings:[],items=Array.isArray(report.items)?report.items:[];
  const message=value=>typeof value==='string'?value:(value?.reason||value?.message||value?.code||'未提供说明');
  const notes=[...errors.map(x=>`错误：${message(x)}`),...warnings.map(x=>`提示：${message(x)}`)];
  const bad=items.filter(x=>x.status!=='converted'&&x.status!=='ok'&&x.status!=='success');
  return `<div class="diagnostic-report"><b class="${report.valid===true?'ok':'err'}">${safe(conversionSummary(report))}</b>${notes.length?'<ul>'+notes.slice(0,80).map(x=>'<li>'+safe(x)+'</li>').join('')+'</ul>':''}${bad.length?'<div class="muted">跳过 / 无效节点及原因（不含 raw 链接或 token）：</div><ul class="report-items">'+bad.slice(0,100).map(x=>`<li>${safe(x.name||'未命名')} · ${safe(x.protocol||'未知协议')} · ${safe(x.status||'skipped')} [${safe(x.code||'unknown')}] — ${safe(x.reason||'未提供原因')}</li>`).join('')+'</ul>':''}${bad.length>100?'<div class="muted">另有 '+(bad.length-100)+' 条，显示上限为 100。</div>':''}</div>`;
}
function renderLinkModal(){
  const mode=currentLinkTab==='clash'?'clash':'general',link=String(currentModalLinks[mode]||'').trim();
  q('#linkText').value=link;UI.setError('#linkError','');
  q('#linkQr').innerHTML='';
  try{if(!link)throw new Error('没有可生成二维码的链接');UI.localQR(link,q('#linkQr'));}
  catch(error){UI.setError('#linkError',error.message);}
  q('#linkTabGeneral').textContent=mode==='clash'?'Clash版':'通用版';
  q('#linkModalTitle').textContent=`${mode==='clash'?'Clash':'通用'}订阅二维码 · 完全本地生成`;
  q('#importBtn').style.display=mode==='clash'?'':'none';q('#importGeneralBtn').style.display=mode==='general'?'':'none';
  q('#linkDiagnostics').innerHTML=mode==='clash'&&currentLinkReport?renderConversionReport(currentLinkReport):'<div class="muted">二维码在本机计算，不会发送地址到第三方。链接含订阅授权，请只分享给信任的设备。</div>';
}
function switchLinkTab(mode){currentLinkTab=mode==='clash'?'clash':'general';renderLinkModal();}
function openLinkModal(link,clashImportUri='',generalImportUris={},openMode='general',report=null,subscriptionId=null){
  ++linkActionVersion;
  const mode=openMode==='clash'?'clash':'general';
  currentModalLinks={general:'',clash:''};currentModalLinks[mode]=String(link||'');
  currentModalClashImports={general:String(clashImportUri||''),clash:String(clashImportUri||'')};
  currentModalGeneralImports={general:{v2rayn:String(generalImportUris.v2rayn||''),v2rayng:String(generalImportUris.v2rayng||'')},clash:{v2rayn:String(generalImportUris.v2rayn||''),v2rayng:String(generalImportUris.v2rayng||'')}};
  currentLinkTab=mode;currentLinkReport=report;currentLinkSubscriptionId=subscriptionId;
  renderLinkModal();UI.openModal('linkModal','#linkText');
}
function closeLinkModal(){++linkActionVersion;UI.invalidate('link-action');UI.closeModal('linkModal');currentModalLinks={general:'',clash:''};currentLinkReport=null;}
async function copyAnyText(text,okMessage='已复制链接'){
  const value=String(text||'').trim();if(!value){toast('没有可复制的链接','err');return false;}
  try{
    if(navigator.clipboard?.writeText)await navigator.clipboard.writeText(value);
    else{
      const active=document.activeElement,area=document.createElement('textarea');area.value=value;area.style.position='fixed';area.style.left='-9999px';document.body.appendChild(area);area.select();
      const copied=document.execCommand('copy');area.remove();if(active?.isConnected)active.focus();if(!copied)throw new Error('复制不可用');
    }
    toast(okMessage,'ok');return true;
  }catch(_error){toast('复制失败，请选中链接后手动复制（不会发送到第三方）','err');return false;}
}
async function copyFromModal(){
  if(currentLinkTab==='clash'&&currentLinkReport?.valid!==true)return toast('Clash 配置无效，请先处理转换诊断','err');
  return copyAnyText(currentModalLinks[currentLinkTab],currentLinkTab==='clash'?'已复制 Clash 链接':'已复制通用链接');
}
function openClashImportFromModal(){
  if(currentLinkReport?.valid!==true)return toast('Clash 配置无效，不能导入','err');
  const uri=currentModalClashImports[currentLinkTab];if(!uri)return toast('当前链接不支持 Clash 导入','err');location.href=uri;
}
function openGeneralImportFromModal(){
  const data=currentModalGeneralImports[currentLinkTab]||{},agent=String(navigator.userAgent||'').toLowerCase();
  const uri=(agent.includes('android')?data.v2rayng:'')||data.v2rayn||data.v2rayng;
  if(!uri)return toast('当前链接不支持通用导入','err');location.href=uri;
}
function normalizeFullUrlForDisplay(raw){
  let value=String(raw||'').trim();if(!value)return '';
  try{const url=new URL(value),host=url.hostname;const privateHost=['127.0.0.1','localhost','0.0.0.0','::1','[::1]'].includes(host)||/^10\./.test(host)||/^192\.168\./.test(host)||/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)||/^127\./.test(host);
    if(privateHost){if(location.hostname!=='localhost'&&location.hostname!=='127.0.0.1')url.hostname=location.hostname;if(location.protocol==='https:')url.protocol='https:';if(url.port==='8780'||!url.port)url.port='';value=url.toString();}
  }catch(_error){}return value;
}
async function subscriptionClashAction(sub,url,intent,clashImportUri,row){
  const version=++linkActionVersion,listVersion=subscriptionsVersion,request=UI.request('link-action',{id:sub.id,intent,version});
  const target=row.querySelector('[data-diagnostics]');target.textContent='正在读取该订阅的转换诊断…';target.setAttribute('aria-busy','true');
  try{
    const result=await api('/api/subscriptions/'+Number(sub.id)+'/diagnostics',{signal:request.signal});
    if(!request.current()||version!==linkActionVersion)return;
    const report=result.report||{};
    if(listVersion===subscriptionsVersion&&row.isConnected)target.innerHTML=renderConversionReport(report);
    if(report.valid!==true){toast('Clash 配置无效（invalid），未复制或生成二维码；原因已显示在该订阅下方','err');return;}
    if(intent==='qr')openLinkModal(url,clashImportUri,{},'clash',report,sub.id);
    else await copyAnyText(url,'已复制 Clash 链接 · '+conversionSummary(report));
  }catch(error){if(request.current()){if(row.isConnected)target.textContent='诊断失败：'+UI.safeText(error.message);UI.reportError(error);}}
  finally{if(request.current()&&row.isConnected)target.removeAttribute('aria-busy');}
}
function renderSubsUI(subscriptions){
  ++subscriptionsVersion;const box=q('#subs');box.innerHTML='';
  if(!subscriptions.length){box.innerHTML='<div class="muted">暂无</div>';return;}
  for(const sub of subscriptions){
    const full=normalizeFullUrlForDisplay(sub.full_url||`${location.origin}${sub.url||''}`),clash=full.endsWith('/clash')?full:full+'/clash';
    const clashImport=`clash://install-config?url=${encodeURIComponent(clash)}&name=${encodeURIComponent((sub.name||'subgo')+'-Clash版')}`;
    const generalImports={v2rayn:`v2rayn://install-config?url=${encodeURIComponent(full)}&remark=${encodeURIComponent((sub.name||'subgo')+'-通用')}`,v2rayng:`v2rayng://install-config?url=${encodeURIComponent(full)}&remark=${encodeURIComponent((sub.name||'subgo')+'-通用')}`};
    const row=document.createElement('div');row.className='src-item';
    row.innerHTML=`<div class="row" style="justify-content:space-between"><div style="flex:1 1 420px"><b>${esc(sub.name||'')}</b><div class="muted">源：${esc((sub.source_names||[]).join(', ')||'-')} · 已选 ${Number((sub.node_hashes||[]).length)} 个${isEnabled(sub.auto_prune_unreachable)?' · 导出时剔除不通（不改选择）':''}</div><input readonly aria-label="通用订阅授权链接" value="${esc(full)}" style="margin-top:8px"></div><div class="row"><button data-act="copy">复制通用</button><button data-act="qr" class="ghost">通用二维码</button><button data-act="copy-clash">复制 Clash</button><button data-act="qr-clash" class="ghost">Clash 二维码</button><button data-act="edit">编辑</button><button data-act="delete" class="ghost">删除</button></div></div><div data-diagnostics aria-live="polite" style="margin-top:8px"></div>`;
    row.querySelector('input').addEventListener('click',event=>event.target.select());
    const actions={copy:()=>{++linkActionVersion;UI.invalidate('link-action');return copyAnyText(full,'已直接复制通用链接');},qr:()=>{UI.invalidate('link-action');openLinkModal(full,clashImport,generalImports);},'copy-clash':()=>subscriptionClashAction(sub,clash,'copy',clashImport,row),'qr-clash':()=>subscriptionClashAction(sub,clash,'qr',clashImport,row),edit:()=>openSubModal(sub),delete:()=>deleteSub(sub.id)};
    for(const [action,handler] of Object.entries(actions)){const button=row.querySelector(`[data-act="${action}"]`);button.addEventListener('click',()=>runAction(button,handler));}
    box.appendChild(row);
  }
}
async function loadSubs(){
  const revision=++subscriptionsRequestVersion,request=UI.request('subscriptions');const result=await api('/api/view/subscriptions',{signal:request.signal});
  if(request.current()&&revision===subscriptionsRequestVersion)renderSubsUI(result.subscriptions||[]);
}
async function deleteSub(id){if(!confirm('确认删除此订阅？授权链接将失效。'))return;await api('/api/subscriptions/'+Number(id),{method:'DELETE'});toast('订阅已删除','ok');await loadSubs();}
// === 精简版编辑订阅交互 ===
let modalSourceFilterId = 'all';

function renderModalSourceFilter() {
  const el = q('#modalSourceFilter');
  if (!el) return;
  el.innerHTML = '<option value="all">全部来源</option>' + sources.map(s => `<option value="${s.id}">${esc(s.name || '#' + s.id)}</option>`).join('');
  el.value = modalSourceFilterId || 'all';
}
const fillModalSourceFilter = renderModalSourceFilter;

function onModalSourceChange(val) {
  modalSourceFilterId = val;
  modalPage = 1;
  renderSubModal();
}

function toggleModalNode(hash, checked) {
  if (checked) selectedNodeHashes.add(hash);
  else selectedNodeHashes.delete(hash);
  const countEl = q('#modalSelectedCount');
  if (countEl) countEl.textContent = `已选 ${selectedNodeHashes.size} 个节点`;
}

function changeModalPage(delta) {
  modalPage += delta;
  renderSubModal();
}

function renderSubModal() {
  let filtered = allNodes;
  if (modalSourceFilterId !== 'all') {
    filtered = filtered.filter(n => String(n.source_id) === String(modalSourceFilterId));
  }
  const countEl = q('#modalSelectedCount');
  if (countEl) countEl.textContent = `已选 ${selectedNodeHashes.size} 个节点`;
  const PAGE_SIZE = 16;
  const total = filtered.length;
  const maxPage = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (modalPage > maxPage) modalPage = maxPage;
  if (modalPage < 1) modalPage = 1;
  const start = (modalPage - 1) * PAGE_SIZE;
  const pageNodes = filtered.slice(start, start + PAGE_SIZE);

  const listEl = q('#modalNodeList');
  if (listEl) {
    if (!pageNodes.length) {
      listEl.innerHTML = '<div class="muted" style="text-align:center;padding:24px">暂无匹配节点</div>';
    } else {
      listEl.innerHTML = '<div class="modal-node-grid">' + pageNodes.map(n => {
        const hash = String(n.node_hash || '');
        const checked = selectedNodeHashes.has(hash) ? 'checked' : '';
        return `<label class="modal-node-item" style="display:flex;align-items:flex-start;gap:8px;padding:9px 11px;border-radius:14px;cursor:pointer">
          <input type="checkbox" data-node-hash="${esc(hash)}" ${checked} onchange="toggleModalNode('${esc(hash)}', this.checked)" style="margin-top:2px" />
          <div style="flex:1;min-width:0">
            <div class="modal-node-title" style="font-size:13px;font-weight:600;word-break:break-all">${esc(n.node_name || '未命名')}</div>
            <div class="modal-node-meta" style="font-size:11px;color:var(--muted);margin-top:2px">${esc(protocolOf(n).toUpperCase())} · ${esc(n.source_name || '#' + n.source_id)}</div>
          </div>
        </label>`;
      }).join('') + '</div>';
    }
  }

  const infoEl = q('#modalPageInfo');
  if (infoEl) infoEl.textContent = `第 ${modalPage} / ${maxPage} 页（候选 ${total} 个）`;
  const prevBtn = q('#modalPrev'), nextBtn = q('#modalNext');
  if (prevBtn) prevBtn.disabled = modalPage <= 1;
  if (nextBtn) nextBtn.disabled = modalPage >= maxPage;
}

function openSubModal(sub = null) {
  ++subSession;
  UI.invalidate('sub-modal'); UI.invalidate('sub-save');
  editingSubId = sub ? Number(sub.id) : null;
  selectedNodeHashes.clear();
  q('#modalSubName').value = sub ? sub.name || '' : '';
  if (q('#modalAutoPrune')) q('#modalAutoPrune').checked = sub ? !!sub.auto_prune_unreachable : false;
  UI.setError('#modalError', '');
  if (sub && Array.isArray(sub.node_hashes)) {
    for (const h of sub.node_hashes) selectedNodeHashes.add(String(h));
  }
  modalPage = 1;
  modalSourceFilterId = 'all';
  fillModalSourceFilter();
  renderSubModal();
  UI.openModal('subModal', '#modalSubName');
}

function closeSubModal() {
  UI.closeModal('subModal');
}

async function saveSubModal() {
  if (subModalLoading || subSaveBusy) return toast('正在保存，请稍候…', 'err');
  const name = q('#modalSubName').value.trim();
  if (!name) return UI.setError('#modalError', '请填写订阅名称');
  const hashes = [...selectedNodeHashes];
  if (!hashes.length) return UI.setError('#modalError', '请先勾选节点');
  const autoPrune = !!q('#modalAutoPrune')?.checked;
  const payload = {
    name,
    node_hashes: hashes,
    auto_prune_unreachable: autoPrune
  };
  subSaveBusy = true;
  UI.setError('#modalError', '');
  const request = UI.request('sub-save', { id: editingSubId });
  try {
    await api('/api/subscriptions' + (editingSubId ? '/' + Number(editingSubId) : ''), {
      method: editingSubId ? 'PUT' : 'POST',
      signal: request.signal,
      body: JSON.stringify(payload)
    });
    if (!request.current()) return;
    closeSubModal();
    await loadSubs();
    toast('订阅已保存', 'ok');
  } catch (error) {
    if (request.current()) {
      UI.setError('#modalError', '保存失败：' + error.message);
      UI.reportError(error);
    }
  } finally {
    subSaveBusy = false;
  }
}

function loadSuiSourceOptions(){
  const select=q('#suiSource');if(!select)return;const previous=select.value;
  const managed=sources.filter(source=>(source.source_type==='sui_api'||isSbuiSource(source)||isXuiSource(source))&&!isLocalSource(source));
  select.innerHTML=managed.length?managed.map(source=>`<option value="${Number(source.id)}">${esc(source.name||'')}${sourceFlavorLabel(source)?' · '+esc(sourceFlavorLabel(source)):''} (${esc(source.panel_url||'')})</option>`).join(''):'<option value="">暂无可管理的源</option>';
  if([...select.options].some(option=>option.value===previous))select.value=previous;
  select.onchange=()=>loadSuiNodes().catch(UI.reportError);
}
async function loadSuiNodes(){
  const select=q('#suiSource'),box=q('#suiNodes'),sourceId=Number(select?.value||0),request=UI.request('sui',{sourceId});
  if(!sourceId){box.innerHTML='<div class="muted">暂无可管理的 SUI/SBUI/3x-ui 源（本地源在节点页管理）</div>';return;}
  box.setAttribute('aria-busy','true');
  try{
    const result=await api(`/api/sui/${sourceId}/inbounds`,{signal:request.signal});
    if(!request.current()||Number(select.value)!==sourceId)return;
    const inbounds=result.inbounds||[];if(!inbounds.length){box.innerHTML='<div class="muted">暂无节点</div>';return;}
    box.innerHTML='<table><thead><tr><th>ID</th><th>备注</th><th>协议</th><th>端口</th><th>状态</th><th>操作</th></tr></thead><tbody></tbody></table>';
    const body=box.querySelector('tbody');
    for(const inbound of inbounds){
      const id=Number(inbound.id||0),row=document.createElement('tr');
      row.innerHTML=`<td title="真实 ID: ${id}">${esc(inbound.display_id||String(id).padStart(3,'0'))}</td><td>${esc(inbound.remark||'')}</td><td>${esc(inbound.protocol||'')}</td><td>${esc(inbound.port||'')}</td><td>${isEnabled(inbound.enable)?'<span class="ok">启用</span>':'<span class="err">停用</span>'}</td><td><div class="row"><button data-act="rename">改名</button><button data-act="delete">删除</button></div></td>`;
      const rename=row.querySelector('[data-act="rename"]'),remove=row.querySelector('[data-act="delete"]');
      rename.addEventListener('click',()=>runAction(rename,()=>renameSuiInbound(sourceId,id,String(inbound.remark||''))));
      remove.addEventListener('click',()=>runAction(remove,()=>deleteSuiInbound(sourceId,id)));body.appendChild(row);
    }
  }catch(error){if(request.current()){box.innerHTML='<div class="err">加载失败：'+esc(UI.safeText(error.message))+'</div>';UI.reportError(error);}}
  finally{if(request.current())box.removeAttribute('aria-busy');}
}
async function quickReality(){
  const sourceId=Number(q('#suiSource')?.value||0);if(!sourceId)return toast('请先选择可管理的源','err');
  const originalName=q('#realityName').value,remark=originalName.trim()||`quick-${Date.now()}`,portText=q('#realityPort').value.trim(),port=portText?Number(portText):0;
  if(port&&(!Number.isInteger(port)||port<1||port>65535))return toast('端口需在 1–65535 之间','err');
  const source=sources.find(s=>Number(s.id)===sourceId);if(!confirm(`确认在 ${source?.name||sourceId} 创建 Reality 节点 ${remark}？`))return;
  await api(`/api/sui/${sourceId}/reality-quick`,{method:'POST',body:JSON.stringify(port?{remark,port}:{remark})});
  if(q('#realityName').value===originalName)q('#realityName').value='';toast('已在已确认的上游源创建 Reality 节点','ok');await refreshAll();await loadSuiNodes();
}
async function renameSuiInbound(sourceId,inboundId,oldRemark=''){
  const value=prompt('输入新备注：',String(oldRemark));if(value===null)return;const remark=String(value||'').trim();if(!remark)return toast('备注不能为空','err');
  await api(`/api/sui/${Number(sourceId)}/inbounds/${Number(inboundId)}/rename`,{method:'PUT',body:JSON.stringify({remark})});toast('上游节点备注已更新','ok');await refreshAll();await loadSuiNodes();
}
async function deleteSuiInbound(sourceId,inboundId){if(!confirm(`确认删除已选源 #${sourceId} 的上游节点 #${inboundId}？`))return;await api(`/api/sui/${Number(sourceId)}/inbounds/${Number(inboundId)}`,{method:'DELETE'});toast('上游节点已删除','ok');await refreshAll();await loadSuiNodes();}

const TASK_ACTIVE=new Set(['queued','running','cancelling']);
const TASK_STATUS={queued:'排队中',running:'运行中',completed:'完成',partial:'部分成功',failed:'失败',cancelling:'正在取消',cancelled:'已取消'};
const TASK_TYPE={sync:'源同步',connectivity:'节点测速'};
const TASK_POLL_MS=4000,TASK_MAX_POLLS=450,TASK_MAX_POLL_TIME=30*60*1000;
let taskState=[],taskRecent={},taskPollTimer=0,taskPollAttempts=0,taskPollStarted=0,taskErrorStreak=0,lastTasksAt=0;
const taskCancelPending=new Set(),taskDetailCache=new Map();
const numberSafe=value=>Number.isFinite(Number(value))?Math.max(0,Number(value)):0;
function stopTaskPolling(){clearTimeout(taskPollTimer);taskPollTimer=0;}
function taskIsActive(task){return TASK_ACTIVE.has(String(task.status));}
function taskScopeLabel(task){
  const scope=task.scope||{};
  if(Array.isArray(scope.node_ids))return `明确节点范围：${scope.node_ids.length} 个真实 ID${scope.node_ids.length?'（'+scope.node_ids.slice(0,20).map(Number).join(', ')+(scope.node_ids.length>20?'…':'')+'）':''}`;
  if(Array.isArray(scope.source_ids))return '明确源范围：'+scope.source_ids.map(id=>sources.find(s=>Number(s.id)===Number(id))?.name||'#'+id).join('、');
  if(scope.source_id)return '源范围：'+(sources.find(s=>Number(s.id)===Number(scope.source_id))?.name||'#'+scope.source_id);
  return scope.all?'服务端调度：所有启用的非本地源':'服务端已冻结任务范围';
}
function taskResultsHTML(task){
  const results=Array.isArray(task.results)?task.results:[],safe=value=>esc(UI.safeText(value));
  return `${task.error?'<div class="err">错误：'+safe(task.error)+'</div>':''}${results.length?'<ul class="task-results">'+results.slice(0,100).map(result=>`<li>${result.source_id?'源 #'+Number(result.source_id):result.node_id?'节点真实 ID #'+Number(result.node_id):'结果'} · ${safe(result.status||'')} ${result.code?'['+safe(result.code)+']':''} · ${safe(result.message||result.reason||result.error||'')}${result.latency_ms!=null?' · '+numberSafe(result.latency_ms)+' ms':''}</li>`).join('')+'</ul>':'<div class="muted">尚无详细结果</div>'}${numberSafe(task.results_truncated)||results.length>100?'<div class="muted">结果已按服务端 / 前端上限截断。</div>':''}`;
}
function scheduleTaskPoll(){
  stopTaskPolling();if(!authenticated||!taskState.some(taskIsActive)||document.hidden)return;
  if(!taskPollStarted)taskPollStarted=Date.now();
  if(taskPollAttempts>=TASK_MAX_POLLS||Date.now()-taskPollStarted>=TASK_MAX_POLL_TIME||taskErrorStreak>=5){UI.setError('#taskError','已达到本轮自动查询上限；任务未被自动取消。请点“刷新任务”继续查看真实状态。');return;}
  taskPollTimer=setTimeout(()=>{++taskPollAttempts;loadTasks(false).catch(UI.reportError);},Math.min(15000,TASK_POLL_MS*(1+taskErrorStreak)));
}
async function taskDetails(id,container){
  const request=UI.request('task-details:'+id,{id}),target=container.querySelector('[data-task-results]');
  try{const result=await api('/api/tasks/'+encodeURIComponent(id),{signal:request.signal});if(!request.current()||!container.isConnected)return;const task=result.task||{};taskDetailCache.set(id,task);if(taskDetailCache.size>100)taskDetailCache.delete(taskDetailCache.keys().next().value);target.innerHTML=taskResultsHTML(task);}
  catch(error){if(request.current()&&container.isConnected)target.textContent='详情加载失败：'+UI.safeText(error.message);}
}
function renderTasks(){
  const strip = q('#taskStrip'), history = q('#taskHistory');
  if (!strip && !history) return;
  const active = taskState.filter(taskIsActive);
  if (strip) {
    strip.innerHTML = '';
    strip.classList.toggle('hide', !active.length);
  }
  if (history) {
    history.innerHTML = '';
    if (!taskState.length) history.innerHTML = '<div class="muted">暂无后台任务。</div>';
  }
  const makeCard = (task, compact = false) => {
    const id = String(task.id), card = document.createElement('div'); card.className = 'task-card';
    const percent = Math.min(100, numberSafe(task.progress_percent));
    card.innerHTML = `<div class="row" style="justify-content:space-between"><b>${esc(TASK_TYPE[task.type]||UI.safeText(task.type||'任务'))} · ${esc(TASK_STATUS[task.status]||UI.safeText(task.status))}</b><span>${numberSafe(task.completed)} / ${numberSafe(task.total)} · 成功 ${numberSafe(task.succeeded)} · 失败 ${numberSafe(task.failed)}</span></div><div class="muted">${esc(UI.safeText(taskScopeLabel(task)))}</div><progress max="100" value="${percent}"></progress><div class="muted">${percent}% · 耗时 ${(numberSafe(task.elapsed_ms)/1000).toFixed(1)} 秒</div>`;
    return card;
  };
  if (strip) for (const task of active.slice(0, 20)) strip.appendChild(makeCard(task, true));
  if (history) for (const task of taskState.slice(0, 50)) history.appendChild(makeCard(task));
}

async function loadTasks(resetBudget=false){
  if(!authenticated)return;stopTaskPolling();
  if(resetBudget){taskPollAttempts=0;taskPollStarted=Date.now();taskErrorStreak=0;}
  const request=UI.request('tasks');
  try{
    const result=await api('/api/tasks',{signal:request.signal});if(!request.current())return;
    const snapshot=result.snapshot||result.data||result,previous=new Map(taskState.map(task=>[String(task.id),task.status]));
    const tasks=snapshot.tasks||[...(snapshot.active||[]),...(snapshot.recent||[])];
    taskState=[...new Map(tasks.map(task=>[String(task.id),task])).values()].slice(0,100);taskRecent=snapshot.recent_success||{};lastTasksAt=Date.now();taskErrorStreak=0;UI.setError('#taskError','');renderTasks();
    const newlyFinished=taskState.filter(task=>previous.has(String(task.id))&&TASK_ACTIVE.has(previous.get(String(task.id)))&&!taskIsActive(task));
    if(newlyFinished.length){
      for(const task of newlyFinished){taskDetailCache.delete(String(task.id));toast(`${TASK_TYPE[task.type]||'任务'}${TASK_STATUS[task.status]||task.status} · 成功 ${numberSafe(task.succeeded)} / 失败 ${numberSafe(task.failed)}`,task.status==='failed'||task.status==='partial'?'err':'ok');}
      await refreshAll();
    }
    if(!taskState.some(taskIsActive)){stopTaskPolling();taskPollAttempts=0;taskPollStarted=0;}
    else scheduleTaskPoll();
  }catch(error){if(request.current()){++taskErrorStreak;UI.setError('#taskError','任务查询失败：'+error.message+'。已展示的是上次状态。');if(resetBudget)UI.reportError(error);scheduleTaskPoll();}}
}
async function startTask(type,scope){
  if(!['sync','connectivity'].includes(type))throw new Error('未知任务类型');
  const request=UI.request('task-start:'+type,{type,scope});
  const result=await api('/api/tasks/'+type,{method:'POST',signal:request.signal,body:JSON.stringify(scope)});if(!request.current()||!authenticated)return null;const task=result.task;
  if(!task?.id)throw new Error('任务未返回 ID，未提示完成');
  if(!task.scope)task.scope={...scope,all:false};taskState=[task,...taskState.filter(x=>String(x.id)!==String(task.id))].slice(0,100);renderTasks();
  toast(`${TASK_TYPE[type]}任务已创建，可查看真实进度 / 取消`,'ok');taskPollAttempts=0;taskPollStarted=Date.now();taskErrorStreak=0;
  if(!taskIsActive(task))await refreshAll();await loadTasks(false);
  return task;
}
async function cancelTask(id){
  id=String(id);if(taskCancelPending.has(id))return;
  const request=UI.request('task-cancel:'+id,{id});taskCancelPending.add(id);renderTasks();
  try{const result=await api('/api/tasks/'+encodeURIComponent(id)+'/cancel',{method:'POST',signal:request.signal,body:'{}'});if(!request.current()||!authenticated)return;if(result.task)taskState=taskState.map(task=>String(task.id)===id?result.task:task);toast('已提交取消请求；以最终 cancelled 状态为准');await loadTasks(true);}
  finally{taskCancelPending.delete(id);if(authenticated)renderTasks();}
}
let adminOriginalUsername='';
async function loadAdminUser(){
  const request=UI.request('admin');const result=await api('/api/admin/user',{signal:request.signal});if(!request.current())return;
  adminOriginalUsername=String(result.username||'');q('#adminUser').value=adminOriginalUsername;q('#adminPass').value='';
  await Promise.all([loadTasks(false),loadLogCenter()]);
}
async function saveAdminUser(){
  const username=q('#adminUser').value.trim(),password=q('#adminPass').value;
  if(!username)return toast('用户名必填','err');if(password&&password.length<6)return toast('密码至少 6 位（或留空不改）','err');
  const changed=username!==adminOriginalUsername||!!password,request=UI.request('admin-save');
  await api('/api/admin/user',{method:'POST',signal:request.signal,body:JSON.stringify({username,password})});if(!request.current())return;
  if(q('#adminPass').value===password)q('#adminPass').value='';
  if(changed){showLogin('账号设置已更新，旧会话已撤销，请重新登录');toast('账号设置已更新，请重新登录','ok');}
  else toast('用户设置已保存（没有提交未实现的自动测速设置）','ok');
}
async function runConnectivityNow(){return checkConnectivity();}

let logsKind='subscription',logOffset=0,logLimit=50,logsTotal=0,logsLoading=false,logsTimer=0;
let logStatsCounts={};
const LOG_KIND_META={
  system:{tab:'#logKindSystem',search:'搜索日志内容（例如 template / sync / 失败）',hint:'运行日志：服务自身输出，与 systemd 日志同源。模板刷新失败、上游同步异常、登录失败都会记录在这里，也支持导出 CSV。'},
  subscription:{tab:'#logKindSubscription',search:'搜索订阅名 / IP / 设备 / User-Agent',hint:'访问日志：每次 /sub/<token> 或 /sub/<token>/clash 拉取记录，含设备识别。分页与自动刷新只在第一页生效。'},
  audit:{tab:'#logKindAudit',search:'搜索操作 / 对象 / 详情',hint:'操作审计：登录成功，以及页面上的新增、修改、删除操作（不含请求体，避免记录密码）。'}
};
function renderLogKind(){
  Object.values(LOG_KIND_META).forEach(m=>{const el=q(m.tab);if(el)el.classList.remove('tab-on')});
  const active=q(LOG_KIND_META[logsKind]?.tab);
  if(active) active.classList.add('tab-on');
  const sys=logsKind==='system';
  [q('#logLevel'),q('#logScope')].forEach(el=>{if(!el)return;el.style.display=sys?'':'none';});
  const kw=q('#logQuery');
  if(kw) kw.placeholder=LOG_KIND_META[logsKind]?.search||'搜索关键词';
  const hint=q('#logHint');
  if(hint) hint.textContent=LOG_KIND_META[logsKind]?.hint||'';
}
async function setLogKind(kind){
  if(kind===logsKind) return;
  logsKind=kind; logOffset=0; renderLogKind(); await loadLogs(0);
}
function logQueryParams(extra={}){
  const p=new URLSearchParams(extra);
  const kw=(q('#logQuery')?.value||'').trim(); if(kw) p.set('q',kw);
  if(logsKind==='system'){
    const lv=(q('#logLevel')?.value||'').trim(); if(lv) p.set('level',lv);
    const sc=(q('#logScope')?.value||'').trim(); if(sc) p.set('scope',sc);
  }
  return p;
}
function logLevelCell(level){
  const l=String(level||'info').toLowerCase();
  if(l==='error') return '<span class="err">错误</span>';
  if(l==='warn') return '<span style="color:#c2740b">警告</span>';
  return '<span class="muted">信息</span>';
}
function logTimeCell(v){
  const d=new Date(v);
  return isNaN(d.getTime())?esc(String(v||'')):d.toLocaleString();
}
function renderLogRows(kind,rows){
  if(!rows.length) return '<div class="muted" style="padding:8px 2px">暂无记录</div>';
  if(kind==='system'){
    return '<div style="overflow-x:auto"><table><thead><tr><th style="width:150px">时间</th><th style="width:64px">级别</th><th style="width:96px">模块</th><th>内容</th></tr></thead><tbody>'+
      rows.map(x=>`<tr><td>${logTimeCell(x.created_at)}</td><td>${logLevelCell(x.level)}</td><td><span class="pill">${esc(x.scope||'app')}</span></td><td style="word-break:break-word">${esc(x.message||'')}${x.detail?`<div class="muted">${esc(x.detail)}</div>`:''}</td></tr>`).join('')+
      '</tbody></table></div>';
  }
  if(kind==='audit'){
    return '<div style="overflow-x:auto"><table><thead><tr><th style="width:150px">时间</th><th style="width:170px">操作</th><th style="width:170px">对象</th><th>详情</th></tr></thead><tbody>'+
      rows.map(x=>`<tr><td>${logTimeCell(x.created_at)}</td><td>${esc(x.action||'')}</td><td><span class="pill">${esc(x.target_type||'')}${x.target_id?` #${esc(x.target_id)}`:''}</span></td><td style="word-break:break-word">${esc(x.detail||'')}</td></tr>`).join('')+
      '</tbody></table></div>';
  }
  return '<div style="overflow-x:auto"><table><thead><tr><th style="width:145px">时间</th><th>订阅</th><th style="width:76px">类型</th><th style="width:85px">下发状态</th><th style="width:140px">设备</th><th style="width:125px">IP</th><th style="width:200px">User-Agent</th></tr></thead><tbody>'+
    rows.map(x=>{
      const ok = x.status !== 'fail';
      const statusBadge = ok
        ? '<span class="pill ok" style="font-weight:700">✓ 成功</span>'
        : `<span class="pill err" style="font-weight:700" title="${esc(x.error_message||'下发失败')}">✕ 失败</span>`;
      return `<tr><td>${logTimeCell(x.created_at)}</td><td><b>${esc(x.subscription_name||'未命名订阅')}</b></td><td><span class="pill">${esc(x.route_type||'')}</span></td><td>${statusBadge}</td><td title="${esc(x.device||'')}">${esc(x.icon||'')} ${esc(x.device||'未知')}</td><td><code>${esc(x.client_ip||'')}</code></td><td title="${esc(x.user_agent||'')}">${esc((x.user_agent||'').slice(0,58))}${(x.user_agent||'').length>58?'…':''}</td></tr>`;
    }).join('')+
    '</tbody></table></div>';
}
async function loadLogs(offset=0){
  const box=q('#logBox');if(!box)return;
  const kind=logsKind,pageOffset=Math.max(0,Number(offset)||0),previousOffset=logOffset,keepTop=box.scrollTop;
  const params=logQueryParams({kind,limit:String(logLimit),offset:String(pageOffset)}),query=params.toString();
  const request=UI.request('logs',{kind,offset:pageOffset,query});logOffset=pageOffset;logsLoading=true;box.setAttribute('aria-busy','true');
  try{
    const result=await api('/api/admin/logs?'+query,{signal:request.signal});
    if(!request.current()||kind!==logsKind)return;
    logsTotal=numberSafe(result.total);box.innerHTML=renderLogRows(kind,result.rows||[]);if(previousOffset===pageOffset)box.scrollTop=keepTop;
    const filter=[params.get('q')?'关键词：'+params.get('q'):'',params.get('level')?'级别：'+params.get('level'):'',params.get('scope')?'模块：'+params.get('scope'):''].filter(Boolean).join('；');
    q('#logPage').textContent=(logsTotal?`共 ${logsTotal} 条 · 第 ${pageOffset+1}–${Math.min(pageOffset+logLimit,logsTotal)} 条`:'共 0 条')+(filter?' · 当前已提交筛选 '+filter:'');
    q('#logPrev').disabled=pageOffset<=0;q('#logNext').disabled=pageOffset+logLimit>=logsTotal;
  }catch(error){if(request.current()){box.innerHTML='<div class="err">日志加载失败：'+esc(UI.safeText(error.message))+'</div>';UI.reportError(error);}}
  finally{if(request.current()){logsLoading=false;box.removeAttribute('aria-busy');}}
}
async function loadLogStats(){
  const request=UI.request('log-stats');
  try{
    const result=await api('/api/admin/logs/stats',{signal:request.signal});if(!request.current())return;
    logStatsCounts=result.stats||{};q('#logCounts').textContent=`运行 ${numberSafe(logStatsCounts.system)} · 访问 ${numberSafe(logStatsCounts.subscription)} · 审计 ${numberSafe(logStatsCounts.audit)}`;
    q('#logRetention').value=String(numberSafe(result.retention_days));
    const select=q('#logScope'),old=select.value;select.innerHTML='<option value="">全部模块</option>'+(result.scopes||[]).map(scope=>`<option value="${esc(scope.scope)}">${esc(scope.scope)} · ${numberSafe(scope.count)}</option>`).join('');if([...select.options].some(option=>option.value===old))select.value=old;
  }catch(error){if(request.current())UI.reportError(error);}
}
async function loadLogCenter(){
  renderLogKind();
  await loadLogStats();
  await loadLogs(0);
}
async function saveLogRetention(){
  const days=Number(q('#logRetention')?.value||0);
  UI.invalidate('log-stats');
  try{
    await api('/api/admin/user',{method:'POST',body:JSON.stringify({log_retention_days:days})});
    toast(days?`日志保留 ${days} 天，超期自动清理`:'日志改为永久保留','ok');await loadLogStats();
  }catch(e){
    toast('保存失败：'+(e&&e.message||e),'err');
  }
}
async function exportLogs(){
  const kind=logsKind,query=logQueryParams({kind}).toString(),request=UI.request('log-export',{kind,query});
  await UI.download('/api/admin/logs/export?'+query,'subgo-'+kind+'-logs.csv',{signal:request.signal});
  if(request.current())toast('已导出已提交筛选的 '+({system:'运行日志',subscription:'访问日志',audit:'审计日志'}[kind]||'日志')+' CSV','ok');
}
async function clearLogs(){
  const kind=logsKind,label={system:'运行日志',subscription:'访问日志',audit:'操作审计'}[kind]||'日志',request=UI.request('log-clear',{kind});
  const stats=await api('/api/admin/logs/stats',{signal:request.signal});if(!request.current()||kind!==logsKind)return;
  const total=numberSafe(stats.stats?.[kind]);
  if(!confirm(`确认清空该类【${label}】全部日志？\n服务端当前统计 ${total} 条（实际数量可能继续变化）。\n无论当前关键词、级别、模块或页码，都删除该类别的全部记录；不是只清空当前筛选的 ${logsTotal} 条。\n不可撤销。`))return;
  const result=await api('/api/admin/logs/clear',{method:'POST',signal:request.signal,body:JSON.stringify({kind})});if(!request.current())return;
  toast(`已清空该类全部日志：${numberSafe(result.removed)} 条${label}`,'ok');await loadLogStats();if(kind===logsKind)await loadLogs(0);
}

function applyBootstrap(data,context={}){
  sources=data.sources||[];
  if(sourceViewId!=='all'&&!sources.some(source=>String(source.id)===sourceViewId))sourceViewId='all';
  renderSourcesUI();renderNodeSourceSelect();setLocalAddVisible();
  if(context.nodeVersion===undefined||context.nodeVersion===nodeViewVersion){
    allNodes=(data.nodes||[]).map(normalizeNodeView);cacheNodes(allNodes);fillProtocols('#nodeProtocol',allNodes);nodeBusy=false;renderNodes();
  }
  if(context.subVersion===undefined||context.subVersion===subscriptionsRequestVersion)renderSubsUI(data.subscriptions||[]);
}
async function refreshAll(){
  const nodeVersion=++nodeViewVersion,subVersion=++subscriptionsRequestVersion;
  UI.invalidate('nodes');UI.invalidate('subscriptions');
  const request=UI.request('bootstrap',{nodeVersion,subVersion,source:sourceViewId});
  const pageY=window.scrollY||0,scrollTop=q('#nodes')?.scrollTop||0;nodeBusy=true;
  try{
    const data=await api('/api/view/bootstrap',{signal:request.signal});if(!request.current())return;
    applyBootstrap(data,request.context);await refreshKernelStatus();
    if(request.current()&&activeTab==='nodes'&&nodeVersion===nodeViewVersion){q('#nodes').scrollTop=scrollTop;window.scrollTo(0,pageY);}
  }catch(error){if(request.current())UI.reportError(error);}
  finally{if(request.current()&&nodeVersion===nodeViewVersion){nodeBusy=false;renderNodeSelection();}}
}
async function init(){
  let initialTab='home';try{const saved=localStorage.getItem('sui_sub_last_tab')||'home';if(['home','nodes','sui','user'].includes(saved))initialTab=saved;}catch(_error){}
  await refreshAll();if(!authenticated)return;switchTab(initialTab);await loadTasks(false);
  if(!logsTimer)logsTimer=setInterval(()=>{
    if(!authenticated||document.hidden||activeTab!=='user'||logsLoading||logOffset>0||logsKind==='audit'||q('#logQuery').value.trim())return;
    if(logsKind==='system'&&(q('#logLevel').value||q('#logScope').value))return;
    loadLogs(0).catch(UI.reportError);
  },5000);
}
const mSaveBtn = q('#modalSaveBtn');
if (mSaveBtn) mSaveBtn._isUnavailable = () => subModalLoading || subSaveBusy;
const bEn = q('#bulkEnableBtn'), bDis = q('#bulkDisableBtn');
if (bEn) bEn._isUnavailable = () => !selectedNodeIds.size || nodeBusy;
if (bDis) bDis._isUnavailable = () => !selectedNodeIds.size || nodeBusy;
UI.setUnauthorizedHandler(()=>{const expired=authenticated;showLogin(expired?'登录已失效，请重新登录':'请登录后继续');if(expired)toast('登录已失效，请重新登录','err');});
UI.registerModal('subModal',closeSubModal);UI.registerModal('linkModal',closeLinkModal);UI.registerModal('addSourceModal',closeAddSourceModal);UI.registerModal('cfFilterModal',closeCfFilterModal);
document.addEventListener('click',event=>{
  const button=event.target.closest?.('button[data-source-action]');if(!button)return;
  const id=Number(button.dataset.sourceId),handlers={focus:focusSource,panel:openSecurePanel,toggle:toggleSourceEnabled,rename:editSourceName,delete:deleteSource};
  const handler=handlers[button.dataset.sourceAction];if(handler)runAction(button,()=>handler(id));
});
document.addEventListener('visibilitychange',()=>{if(document.hidden)stopTaskPolling();else if(authenticated&&taskState.some(taskIsActive))loadTasks(true).catch(UI.reportError);});
window.addEventListener('unhandledrejection',event=>{event.preventDefault();UI.reportError(event.reason);});
document.querySelectorAll('input,select,textarea').forEach(input=>{if(!input.getAttribute('aria-label')&&!input.labels?.length)input.setAttribute('aria-label',input.placeholder||({nodeSourceSelect:'节点来源',suiSource:'上游来源',logRetention:'日志保留天数',logLevel:'日志级别',logScope:'日志模块',modalSourceFilter:'候选来源筛选',modalAutoPrune:'导出时自动剔除不通节点',linkText:'订阅授权链接'})[input.id]||input.id||'输入');});
q('#modalAutoPrune')?.addEventListener('change',()=>{});
q('#lp')?.addEventListener('keydown',event=>{if(event.key==='Enter')login().catch(UI.reportError);});
try{applyTheme(localStorage.getItem('sui_sub_theme')||'dark');}catch(_error){applyTheme('dark');}
checkAuth().catch(UI.reportError);
