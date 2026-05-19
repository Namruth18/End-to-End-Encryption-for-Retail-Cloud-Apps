/* ═══ 3D CANVAS PARTICLE FIELD ═══ */
(function(){
  const cv=document.getElementById('canvas3d');
  const ctx=cv.getContext('2d');
  let W,H,pts=[],lines=[];
  const N=120;
  function resize(){W=cv.width=window.innerWidth;H=cv.height=window.innerHeight}
  resize();window.addEventListener('resize',resize);
  for(let i=0;i<N;i++){pts.push({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.3,vy:(Math.random()-.5)*.3,r:Math.random()*1.5+.3,pulse:Math.random()*Math.PI*2})}
  let mouse={x:W/2,y:H/2};
  document.addEventListener('mousemove',e=>{mouse.x=e.clientX;mouse.y=e.clientY});
  let t=0;
  function draw(){
    ctx.clearRect(0,0,W,H);
    t+=0.008;
    /* Rotating hex grid in background */
    ctx.save();
    ctx.translate(W*.15,H*.5);
    ctx.rotate(t*.05);
    for(let i=0;i<3;i++){
      const r=120+i*80;
      ctx.beginPath();
      for(let a=0;a<6;a++){const ang=a*Math.PI/3;ctx.lineTo(Math.cos(ang)*r,Math.sin(ang)*r)}
      ctx.closePath();
      ctx.strokeStyle=`rgba(0,210,255,${.015-i*.004})`;ctx.stroke();
    }
    ctx.restore();
    /* Second hex far right */
    ctx.save();
    ctx.translate(W*.88,H*.3);
    ctx.rotate(-t*.04);
    for(let i=0;i<3;i++){
      const r=80+i*60;
      ctx.beginPath();
      for(let a=0;a<6;a++){const ang=a*Math.PI/3;ctx.lineTo(Math.cos(ang)*r,Math.sin(ang)*r)}
      ctx.closePath();
      ctx.strokeStyle=`rgba(0,255,140,${.012-i*.003})`;ctx.stroke();
    }
    ctx.restore();
    /* Grid lines */
    const gs=80;
    ctx.strokeStyle='rgba(0,210,255,0.018)';ctx.lineWidth=1;
    for(let x=0;x<W;x+=gs){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke()}
    for(let y=0;y<H;y+=gs){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke()}
    /* Particles + connections */
    pts.forEach(p=>{
      p.x+=p.vx+(mouse.x-W/2)*0.00008;p.y+=p.vy+(mouse.y-H/2)*0.00008;
      if(p.x<0||p.x>W)p.vx*=-1;if(p.y<0||p.y>H)p.vy*=-1;
      p.x=Math.max(0,Math.min(W,p.x));p.y=Math.max(0,Math.min(H,p.y));
      p.pulse+=.02;
      const a=.3+Math.sin(p.pulse)*.15;
      ctx.beginPath();ctx.arc(p.x,p.y,p.r*(1+Math.sin(p.pulse)*.3),0,Math.PI*2);
      ctx.fillStyle=`rgba(0,210,255,${a})`;ctx.fill();
    });
    const MD=120;
    for(let i=0;i<pts.length;i++){
      for(let j=i+1;j<pts.length;j++){
        const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y;
        const d=Math.sqrt(dx*dx+dy*dy);
        if(d<MD){
          const a=(1-d/MD)*0.12;
          ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);
          ctx.strokeStyle=`rgba(0,210,255,${a})`;ctx.lineWidth=.6;ctx.stroke();
        }
      }
    }
    /* Scan line sweep */
    const sy=(t*60)%H;
    const sg=ctx.createLinearGradient(0,sy-30,0,sy+30);
    sg.addColorStop(0,'rgba(0,210,255,0)');
    sg.addColorStop(.5,'rgba(0,210,255,0.015)');
    sg.addColorStop(1,'rgba(0,210,255,0)');
    ctx.fillStyle=sg;ctx.fillRect(0,sy-30,W,60);
    requestAnimationFrame(draw);
  }
  draw();
})();

/* ═══ APP LOGIC ═══ */
const API = window.location.origin; // works on any host/port
let me=null,openId=null,openMsgData=null,pollTimer=null,lastPoll=new Date().toISOString();
let attachFile=null;

document.addEventListener('DOMContentLoaded',()=>{
  const s=localStorage.getItem('sc5');
  if(s){try{me=JSON.parse(s);showApp();loadStats();startPolling();}catch{localStorage.removeItem('sc5');}}
  document.getElementById('lP').onkeydown=e=>{if(e.key==='Enter')doLogin();};
  document.getElementById('rC').onkeydown=e=>{if(e.key==='Enter')doReg();};
  document.querySelectorAll('.ni').forEach(el=>el.addEventListener('click',()=>goS(el.dataset.sec)));
  document.getElementById('msgModal').onclick=e=>{if(e.target===document.getElementById('msgModal'))closeModal();};
});

function sw(t){clearM();['L','R'].forEach(x=>{document.getElementById('t'+x).classList.toggle('on',(x==='L')===(t==='login'));document.getElementById('p'+x).classList.toggle('on',(x==='L')===(t==='login'));});}
function showM(tx,ty){const e=document.getElementById('amsg');e.textContent=tx;e.className='amsg '+ty;e.style.display='block';}
function clearM(){document.getElementById('amsg').style.display='none';}


async function doLogin(){
  const u=document.getElementById('lU').value.trim(),p=document.getElementById('lP').value,t=document.getElementById('lT').value.trim();
  clearM();if(!u||!p){showM('// error: fill in username and password','err');return;}
  const btn=document.getElementById('btnL');btn.disabled=true;btn.textContent='[ AUTHENTICATING... ]';
  try{
    const r=await fetch(`${API}/api/login`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p,totp_code:t})});
    const d=await r.json();
    if(d.needs_2fa){document.getElementById('tfaField').style.display='block';showM('// 2FA required — enter your 6-digit code','ok');btn.disabled=false;btn.textContent='[ AUTHENTICATE ]';return;}
    if(d.success){me={username:d.username,role:d.role,token:d.token};localStorage.setItem('sc5',JSON.stringify(me));toast('ACCESS GRANTED','success');showApp();loadStats();startPolling();}
    else showM('// error: '+(d.message||'invalid credentials'),'err');
  }catch(err){showM('// connection error — make sure Flask server is running','err');}
  finally{btn.disabled=false;btn.textContent='[ AUTHENTICATE ]';}
}

async function doReg(){
  const u=document.getElementById('rU').value.trim(),p=document.getElementById('rP').value,c=document.getElementById('rC').value;
  clearM();if(!u||!p||!c){showM('// error: all fields required','err');return;}
  if(u.length<3){showM('// error: username >= 3 characters','err');return;}
  if(p.length<6){showM('// error: password >= 6 characters','err');return;}
  if(p!==c){showM('// error: passwords do not match','err');return;}
  const btn=document.getElementById('btnR');btn.disabled=true;btn.textContent='[ CREATING... ]';
  try{const r=await fetch(`${API}/api/register`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});const d=await r.json();
    if(d.success){showM('// success: account created — sign in now','ok');document.getElementById('lU').value=u;document.getElementById('rP').value='';document.getElementById('rC').value='';setTimeout(()=>sw('login'),1100);}
    else showM('// error: '+(d.message||'failed'),'err');
  }catch(err){showM('// server unreachable — start Flask then retry','err');}
  finally{btn.disabled=false;btn.textContent='[ CREATE ACCOUNT ]';}
}

function showApp(){
  document.getElementById('authWrap').style.display='none';
  document.getElementById('appShell').style.display='block';
  document.getElementById('sbN').textContent=me.username;
  document.getElementById('sbR').textContent=me.role.replace('_',' ');
  document.getElementById('wN').textContent=me.username.toUpperCase();
  document.getElementById('accessDesc').textContent=
    me.role==='admin'
      ? 'ADMIN — Full system access including audit log, all messages and encrypted files.'
      : 'USER — Full access to compose, inbox, secure files and 2FA security.';
  const av=document.getElementById('sbAv');av.textContent=me.username[0].toUpperCase();av.className='uav '+me.role;
  if(me.role==='admin'){
    document.querySelectorAll('.admin-only').forEach(el=>{
      const tag=el.tagName.toLowerCase();
      // Sidebar <li> items use flex, stat cards/grids use block
      // BUT skip <div class="sec"> pages — only show via goS()
      if(tag==='div' && el.classList.contains('sec')) return;
      el.style.display=(tag==='li')?'flex':'block';
    });
  }
  loadUsers();load2FAStatus();
}
async function doSignout(){
  if(me?.token)await fetch(`${API}/api/logout`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:me.token})}).catch(()=>{});
  clearInterval(pollTimer);localStorage.removeItem('sc5');location.reload();
}
function goS(sec){
  document.querySelectorAll('.sec').forEach(s=>{s.classList.remove('on');s.style.display='none';});
  const el=document.getElementById(sec);
  if(el){el.style.display='block';el.classList.add('on');}
  document.querySelectorAll('.ni').forEach(n=>n.classList.toggle('on',n.dataset.sec===sec));
  if(sec==='inbox')loadInbox();
  if(sec==='audit')loadAudit();
  if(sec==='compose'){loadUsers();loadCategories();}
  if(sec==='files')loadFiles();
  if(sec==='tfa')load2FAStatus();
  if(sec==='sent')loadSent();
  if(sec==='groups'){
    loadGroups();
    // Show create panel only for admin
    const cc = document.getElementById('grpCreateCard');
    if (cc) cc.style.display = me.role === 'admin' ? '' : 'none';
    if (me.role === 'admin') loadGroupMembersDropdown();
  }
  if(sec==='keys'){loadKeys();loadUsers();loadSharedKeys();}
  if(sec==='keyshare')loadKeySharePage();
  if(sec==='usermgr')loadAllUsers();
}

async function loadStats(){
  try{const d=await(await fetch(`${API}/api/stats?username=${me.username}`)).json();
    document.getElementById('dUnread').textContent=d.unread;
    document.getElementById('dSent').textContent=d.total_sent;
    document.getElementById('dFiles').textContent=d.total_files;
    if(me.role==='admin')document.getElementById('dUsers').textContent=d.total_users;
    const ib=document.getElementById('inboxBadge');
    if(d.unread>0){ib.textContent=d.unread;ib.style.display='inline';}else ib.style.display='none';
  }catch{}
}
function startPolling(){
  pollTimer=setInterval(async()=>{
    try{const d=await(await fetch(`${API}/api/messages/poll?username=${me.username}&since=${lastPoll}`)).json();
      if(d.new_count>0){lastPoll=new Date().toISOString();toast(`${d.new_count} NEW MESSAGE(S) RECEIVED`,'info');loadStats();if(document.getElementById('inbox').classList.contains('on'))loadInbox();}
    }catch{}
  },5000);
}

async function loadUsers(){
  try{
    const u=await(await fetch(`${API}/api/users`)).json();
    const sel=document.getElementById('cRec');
    sel.innerHTML='<option value="">-- select recipient --</option>';
    const shareSel=document.getElementById('shareToUser');
    shareSel.innerHTML='<option value="">-- pick user --</option>';
    u.forEach(x=>{
      if(x.username!==me.username){
        const o=document.createElement('option');
        o.value=x.username;
        o.textContent=`${x.username}  [${x.role.replace('_',' ').toUpperCase()}]`;
        sel.appendChild(o);
        shareSel.appendChild(o.cloneNode(true));
      }
    });
  }catch{}
}

async function loadCategories(){
  try{
    const d=await(await fetch(`${API}/api/categories?username=${me.username}`)).json();
    const pills=document.getElementById('catPills');
    pills.innerHTML='';
    document.getElementById('cCat').value='';
    const CAT_COLORS={billing:'billing',transaction:'transaction',customer:'customer',general:'general'};
    d.categories.forEach(cat=>{
      const p=document.createElement('div');
      p.className=`cpick ${CAT_COLORS[cat]||'general'}`;
      p.textContent=cat.toUpperCase();
      p.onclick=()=>{
        document.querySelectorAll('#catPills .cpick').forEach(x=>x.classList.remove('sel'));
        p.classList.add('sel');
        document.getElementById('cCat').value=cat;
      };
      pills.appendChild(p);
    });
    // auto-select first if only one option
    if(d.categories.length===1){
      pills.querySelector('.cpick')?.click();
    }
  }catch{}
}

/* ── Attachment handlers ── */
function onAttDrop(e){e.preventDefault();document.getElementById('attZone').classList.remove('has-file');const f=e.dataTransfer.files[0];if(f)onAttSelect(f);}
function onAttSelect(file){
  if(!file)return;
  if(file.size>5*1024*1024){toast('ATTACHMENT MAX 5MB','error');return;}
  attachFile=file;
  const sz=file.size<1024?file.size+'B':file.size<1048576?(file.size/1024).toFixed(1)+'KB':(file.size/1048576).toFixed(1)+'MB';
  const fn=document.getElementById('attFilename');fn.textContent='📎 '+file.name+' ('+sz+')';fn.style.display='block';
  document.getElementById('attClearBtn').style.display='inline-block';
  document.getElementById('attZone').classList.add('has-file');
}
function clearAttachment(e){e.stopPropagation();attachFile=null;document.getElementById('attFilename').style.display='none';document.getElementById('attClearBtn').style.display='none';document.getElementById('attZone').classList.remove('has-file');document.getElementById('attFileIn').value='';}

async function doSend(){
  const to=document.getElementById('cRec').value,content=document.getElementById('cMsg').value.trim();
  const category=document.getElementById('cCat').value;
  if(!to){toast('SELECT A RECIPIENT','error');return;}
  if(!content){toast('MESSAGE IS EMPTY','error');return;}
  if(!category){toast('SELECT A CATEGORY','error');return;}
  const btn=document.getElementById('btnSend');btn.disabled=true;btn.textContent='[ ENCRYPTING... ]';
  let attachment=null;
  if(attachFile){
    try{
      const b64=await new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(r.result.split(',')[1]);r.onerror=rej;r.readAsDataURL(attachFile);});
      attachment={name:attachFile.name,mime:attachFile.type||'application/octet-stream',data_b64:b64};
    }catch{toast('ATTACHMENT READ ERROR','error');btn.disabled=false;btn.textContent='[ ENCRYPT & TRANSMIT ]';return;}
  }
  try{
    const body={from:me.username,to,content,category};
    if(attachment)body.attachment=attachment;
    const r=await fetch(`${API}/api/messages/send`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(d.success){
      toast('ENCRYPTED & TRANSMITTED','success');
      document.getElementById('cMsg').value='';
      document.getElementById('cCat').value='';
      document.querySelectorAll('#catPills .cpick').forEach(p=>p.classList.remove('sel'));
      clearAttachment({stopPropagation:()=>{}});
      loadStats();
    }else toast(d.error||'SEND FAILED','error');
  }catch{toast('NETWORK ERROR','error');}
  finally{btn.disabled=false;btn.textContent='[ ENCRYPT & TRANSMIT ]';}
}

async function loadInbox(){
  try{const msgs=await(await fetch(`${API}/api/messages?username=${me.username}`)).json();
    const list=document.getElementById('msgList');list.innerHTML='';
    if(!msgs.length){list.innerHTML='<div class="empty-st">// inbox clear — no encrypted messages</div>';return;}
    msgs.forEach(m=>{
      const row=document.createElement('div');
      row.className='irow-ext '+(m.is_read?'':'unread');
      const cat=m.category||'general';
      const cipher=m.ciphertext||'';
      // Main click area (all except the shared-key button)
      row.innerHTML=`
        <div class="irow-main" onclick="openMsg(${JSON.stringify(m).replace(/"/g,'&quot;')})">
          <div class="i-num">#${m.id}</div>
          <div class="i-from">${m.sender}</div>
          <div><span class="cpill ${cat}">${cat}</span></div>
          <div class="i-time">${new Date(m.sent_at).toLocaleString()}</div>
          <div><span class="sbadge ${m.is_read?'read':'new'}">${m.is_read?'READ':'NEW'}</span></div>
        </div>
        <div class="irow-sk-cell">
          <button class="btn-use-sk" title="Decrypt this message using a shared key" onclick="event.stopPropagation();ksOpenWithMsg(${m.id},'${cipher.replace(/'/g,"\'").substring(0,300)}','${m.sender}','${new Date(m.sent_at).toLocaleString()}','${cat}')">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
            USE SHARED KEY
          </button>
        </div>`;
      list.appendChild(row);
    });
    // Store full ciphertext map so we can retrieve it by message id
    window._inboxCiphertextMap = {};
    msgs.forEach(m=>{ window._inboxCiphertextMap[m.id]=m.ciphertext||''; });
  }catch{}
}

function openMsg(m){
  if(typeof m==='string'){try{m=JSON.parse(m);}catch{return;}}
  openId=m.id;openMsgData=m;
  const cat=m.category||'general';
  document.getElementById('mFrom').textContent=m.sender;
  document.getElementById('mCat').innerHTML=`<span class="cpill ${cat}">${cat}</span>`;
  document.getElementById('mTime').textContent=new Date(m.sent_at).toLocaleString();
  document.getElementById('mKeyId').textContent=m.key_id||'—';
  document.getElementById('mCipher').textContent=(m.ciphertext||'').substring(0,160)+'…';
  document.getElementById('mPlain').textContent='// awaiting decryption command...';
  document.getElementById('mVerify').style.display='none';
  document.getElementById('mIntegrity').style.display='none';
  document.getElementById('chatBox').innerHTML='<div class="empty-st">// click LOAD to view conversation history</div>';
  document.getElementById('attResultBox').style.display='none';
  document.getElementById('msgModal').classList.add('open');
}
function closeModal(){document.getElementById('msgModal').classList.remove('open');openId=null;openMsgData=null;}
function dlAttachment(url,name){const a=document.createElement('a');a.href=url;a.download=name;document.body.appendChild(a);a.click();document.body.removeChild(a);}

async function doDecrypt(){
  if(!openId)return;
  try{const r=await fetch(`${API}/api/messages/decrypt`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message_id:openId,username:me.username})});
    const d=await r.json();
    if(d.plaintext){
      document.getElementById('mPlain').textContent=d.plaintext;
      document.getElementById('mVerify').style.display='inline-flex';
      const ib=document.getElementById('mIntegrity');ib.style.display='block';
      if(d.integrity&&d.integrity.includes('PASS')){ib.className='v-badge';ib.innerHTML='<svg width="10" height="10" viewBox="0 0 24 24" fill="none"><path d="M12 2L4 5.5v5.5c0 5 3.3 9.7 8 11 4.7-1.3 8-6 8-11V5.5L12 2z" stroke="currentColor" stroke-width="2"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>'+d.integrity;}
      else{ib.className='fail-badge';ib.innerHTML='⚠ INTEGRITY FAILURE — POSSIBLE TAMPERING DETECTED';}
      toast('DECRYPTION SUCCESSFUL · HMAC VERIFIED','success');loadInbox();loadStats();
      // ── Show attachment if present ──────────────────────────────────────────
      const arb=document.getElementById('attResultBox');const arc=document.getElementById('attResultContent');
      if(d.attachment){
        arb.style.display='block';
        if(d.attachment.error){arc.innerHTML=`<div style="color:var(--danger);font-family:'JetBrains Mono',monospace;font-size:10px">⚠ ${d.attachment.error}</div>`;}
        else{
          const mime=d.attachment.mime||'';const name=d.attachment.name||'file';
          const url='data:'+mime+';base64,'+d.attachment.data_b64;
          let h=`<button class="att-dl-btn" onclick="dlAttachment('${url}','${name}')">⬇ DOWNLOAD — ${name}</button>`;
          if(mime.startsWith('image/'))h+=`<img src="${url}" class="att-img-preview" alt="${name}">`;
          arc.innerHTML=h;
        }
      }else arb.style.display='none';
    }else toast(d.error||'DECRYPTION FAILED','error');
  }catch{toast('NETWORK ERROR','error');}
}

async function loadHistory(){
  if(!openMsgData)return;
  const other=openMsgData.sender===me.username?openMsgData.recipient:openMsgData.sender;
  try{const msgs=await(await fetch(`${API}/api/messages/history?me=${me.username}&other=${other}`)).json();
    const box=document.getElementById('chatBox');box.innerHTML='';
    if(!msgs.length){box.innerHTML='<div class="empty-st">// no history found</div>';return;}
    msgs.forEach(m=>{
      const b=document.createElement('div');b.className='cbub '+(m.sender===me.username?'me':'them');
      b.innerHTML=`<span style="color:var(--muted);font-family:'JetBrains Mono',monospace;font-size:10px">🔒 encrypted · open to decrypt</span><div class="cbub-meta">${m.sender} · ${new Date(m.sent_at).toLocaleString()} · <span class="cpill ${m.category||'general'}">${m.category||'general'}</span></div>`;
      box.appendChild(b);
    });
    box.scrollTop=box.scrollHeight;
  }catch{}
}

function handleDrop(e){e.preventDefault();document.getElementById('dz').classList.remove('drag');const f=e.dataTransfer.files[0];if(f)uploadFile(f);}
async function uploadFile(file){
  if(!file)return;if(file.size>10*1024*1024){toast('FILE TOO LARGE (MAX 10MB)','error');return;}
  toast('ENCRYPTING & UPLOADING...','info');
  const fd=new FormData();fd.append('file',file);fd.append('username',me.username);
  try{const r=await fetch(`${API}/api/files/upload`,{method:'POST',body:fd});const d=await r.json();
    if(d.success){toast(`${file.name} ENCRYPTED & STORED`,'success');loadFiles();loadStats();}else toast(d.error||'UPLOAD FAILED','error');
  }catch{toast('UPLOAD ERROR','error');}
}
async function loadFiles(){
  try{const files=await(await fetch(`${API}/api/files?username=${me.username}`)).json();
    const list=document.getElementById('fileList');list.innerHTML='';
    if(!files.length){list.innerHTML='<div class="empty-st">// vault empty — no encrypted files</div>';return;}
    files.forEach(f=>{
      const row=document.createElement('div');row.className='file-row';
      const sz=f.file_size<1024?f.file_size+'B':f.file_size<1048576?(f.file_size/1024).toFixed(1)+'KB':(f.file_size/1048576).toFixed(1)+'MB';
      row.innerHTML=`<div style="font-weight:700;font-size:12px;color:var(--text)">🔒 ${f.orig_name}</div><div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--muted)">${sz}</div><div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--muted)">${new Date(f.uploaded_at).toLocaleDateString()}</div><div><button class="btn btn-c2" style="font-size:9px;padding:6px 12px" onclick="dlFile(${f.id},'${f.orig_name}')">⬇ DECRYPT &amp; DL</button></div>`;
      list.appendChild(row);
    });
  }catch{}
}
async function dlFile(id,name){
  toast('DECRYPTING...','info');
  try{const r=await fetch(`${API}/api/files/download/${id}?username=${me.username}`);
    if(!r.ok){const e=await r.json();toast(e.error||'DOWNLOAD FAILED','error');return;}
    const blob=await r.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=name;document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);
    toast(`${name} DECRYPTED & DOWNLOADED`,'success');
  }catch{toast('DOWNLOAD ERROR','error');}
}

/* ════════════════════════════════════════════════════════════
   2FA — QR-BASED TOTP SETUP
════════════════════════════════════════════════════════════ */
let _tfaQrInstance = null;   // holds qrcode.js instance so we can clear it

async function load2FAStatus() {
  try {
    const d   = await (await fetch(`${API}/api/stats?username=${me.username}`)).json();
    const bar = document.getElementById('tfaStatusBar');
    const btn = document.getElementById('btnDisable');
    const setupBtn = document.getElementById('btnSetup');
    if (d.totp_enabled) {
      bar.innerHTML = `
        <div class="tfa-status-on">
          <div class="ts-icon on">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L4 5.5v5.5c0 5 3.3 9.7 8 11 4.7-1.3 8-6 8-11V5.5L12 2z" stroke="#00ff8c" stroke-width="2"/>
              <path d="M9 12l2 2 4-4" stroke="#00ff8c" stroke-width="2" stroke-linecap="round"/>
            </svg>
          </div>
          <div>
            <div class="ts-txt-title" style="color:var(--c2)">✓ 2FA IS ACTIVE</div>
            <div class="ts-txt-desc">Your account is protected. Every login now requires your rotating 6-digit OTP code from your authenticator app.</div>
          </div>
        </div>`;
      if (btn) btn.style.display = 'flex';
      if (setupBtn) setupBtn.style.display = 'none';
      // Hide setup box if it was open
      const box = document.getElementById('tfaSetupBox');
      if (box) box.style.display = 'none';
    } else {
      bar.innerHTML = `
        <div class="tfa-status-off">
          <div class="ts-icon off">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
              <rect x="5" y="11" width="14" height="10" rx="2" stroke="#ffd600" stroke-width="2"/>
              <path d="M8 11V7a4 4 0 018 0v4" stroke="#ffd600" stroke-width="2" stroke-linecap="round"/>
            </svg>
          </div>
          <div>
            <div class="ts-txt-title" style="color:var(--c5)">2FA IS DISABLED</div>
            <div class="ts-txt-desc">Your account uses password-only login. Click "Setup Two-Factor Auth" below to add QR-based TOTP protection.</div>
          </div>
        </div>`;
      if (btn) btn.style.display = 'none';
      if (setupBtn) setupBtn.style.display = '';
    }
  } catch(e) { console.error('2FA status error:', e); }
}

async function setup2FA() {
  const setupBtn = document.getElementById('btnSetup');
  if (setupBtn) { setupBtn.disabled = true; setupBtn.textContent = '// generating...'; }

  try {
    const d = await (await fetch(`${API}/api/2fa/setup`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username: me.username })
    })).json();

    if (d.error) { toast(d.error, 'error'); return; }

    // Show setup box and hide steps explainer
    const box   = document.getElementById('tfaSetupBox');
    const steps = document.getElementById('tfaSteps');
    if (box)   box.style.display   = '';
    if (steps) steps.style.display = 'none';

    // Display the secret text
    const secEl = document.getElementById('tfaSecret');
    if (secEl) secEl.textContent = d.secret;

    // Activate step 2 in the stepper
    _tfaSetStep(2);

    // Render QR code using qrcode.js
    _tfaRenderQR(d.otpauth);

    // Focus OTP input
    setTimeout(() => {
      const inp = document.getElementById('tfaCode');
      if (inp) inp.focus();
    }, 600);

    toast('QR CODE READY — SCAN WITH YOUR AUTHENTICATOR APP', 'info');

  } catch(e) {
    console.error(e);
    toast('2FA SETUP ERROR', 'error');
  } finally {
    if (setupBtn) { setupBtn.disabled = false; setupBtn.textContent = ''; }
    // Restore button label properly
    const setupBtn2 = document.getElementById('btnSetup');
    if (setupBtn2) setupBtn2.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><rect x="5" y="11" width="14" height="10" rx="2" stroke="currentColor" stroke-width="2"/><path d="M8 11V7a4 4 0 018 0v4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="16" r="1.5" fill="currentColor"/></svg>
      SETUP TWO-FACTOR AUTH`;
  }
}

function _tfaRenderQR(otpauthUrl) {
  const loading = document.getElementById('tfaQrLoading');
  const canvas  = document.getElementById('tfaQrCanvas');
  const frame   = document.getElementById('tfaQrFrame');
  if (!canvas || !frame) return;

  // Clear previous instance
  if (_tfaQrInstance) {
    canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height);
    _tfaQrInstance = null;
  }
  canvas.style.display = 'none';
  if (loading) loading.style.display = 'flex';

  // Small delay so the spinner shows
  setTimeout(() => {
    try {
      if (typeof QRCode === 'undefined') {
        // qrcode.js not loaded — show manual entry fallback message
        if (loading) loading.innerHTML = `
          <div style="text-align:center;color:var(--c5);font-family:'JetBrains Mono',monospace;font-size:10px;padding:12px">
            <div style="font-size:20px;margin-bottom:8px">⚠</div>
            QR library unavailable.<br>Use the manual secret below.
          </div>`;
        return;
      }

      // Create QR with dark-mode styling
      _tfaQrInstance = new QRCode(canvas, {
        text:           otpauthUrl,
        width:          200,
        height:         200,
        colorDark:      '#deeeff',
        colorLight:     '#060f1e',
        correctLevel:   QRCode.CorrectLevel.H
      });

      // Hide loading, show canvas
      if (loading) loading.style.display = 'none';
      canvas.style.display = 'block';
      _tfaSetStep(2);

    } catch(err) {
      console.error('QR render error:', err);
      if (loading) loading.innerHTML = `
        <div style="text-align:center;color:var(--danger);font-family:'JetBrains Mono',monospace;font-size:10px;padding:12px">
          QR error — use manual secret
        </div>`;
    }
  }, 100);
}

function _tfaSetStep(n) {
  [1,2,3].forEach(i => {
    const el = document.getElementById('tfaStep' + i);
    if (!el) return;
    el.classList.toggle('active',    i === n);
    el.classList.toggle('completed', i < n);
  });
}

function onTfaCodeInput(inp) {
  // Auto-format to digits only, advance step indicator
  inp.value = inp.value.replace(/\D/g, '');
  if (inp.value.length === 6) _tfaSetStep(3);
  else if (inp.value.length > 0) _tfaSetStep(2);
}

function copySecret() {
  const el = document.getElementById('tfaSecret');
  if (!el) return;
  const txt = el.textContent.trim();
  if (!txt) return;
  navigator.clipboard.writeText(txt).then(() => {
    toast('SECRET COPIED TO CLIPBOARD', 'success');
  }).catch(() => {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = txt;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    toast('SECRET COPIED', 'success');
  });
}

async function verify2FA() {
  const codeEl = document.getElementById('tfaCode');
  const hint   = document.getElementById('tfaCodeHint');
  const code   = codeEl?.value.trim() || '';
  if (!code || code.length !== 6) {
    toast('ENTER THE 6-DIGIT CODE FROM YOUR APP', 'error');
    if (codeEl) { codeEl.classList.add('shake'); setTimeout(() => codeEl.classList.remove('shake'), 500); }
    return;
  }

  const btn = document.querySelector('.btn-tfa-verify');
  if (btn) { btn.disabled = true; btn.textContent = '// verifying...'; }
  if (hint) { hint.textContent = '// verifying code...'; hint.style.color = 'var(--muted)'; }

  try {
    const d = await (await fetch(`${API}/api/2fa/verify`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username: me.username, code })
    })).json();

    if (d.success) {
      _tfaSetStep(3);
      if (hint) { hint.textContent = '✓ Verified — 2FA is now active!'; hint.style.color = 'var(--c2)'; }
      toast('2FA ENABLED — YOUR ACCOUNT IS NOW PROTECTED', 'success');
      // Brief success pause then refresh status
      setTimeout(() => {
        const box   = document.getElementById('tfaSetupBox');
        const steps = document.getElementById('tfaSteps');
        if (box)   box.style.display   = 'none';
        if (steps) steps.style.display = '';
        if (codeEl) codeEl.value = '';
        load2FAStatus();
      }, 1800);
    } else {
      toast(d.message || 'INVALID CODE — TRY AGAIN', 'error');
      if (hint) { hint.textContent = '✕ Code incorrect — check your app and try again'; hint.style.color = 'var(--danger)'; }
      if (codeEl) { codeEl.value = ''; codeEl.classList.add('shake'); setTimeout(() => codeEl.classList.remove('shake'), 500); codeEl.focus(); }
    }
  } catch(e) {
    console.error(e);
    toast('VERIFICATION ERROR', 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 2L4 5.5v5.5c0 5 3.3 9.7 8 11 4.7-1.3 8-6 8-11V5.5L12 2z" stroke="currentColor" stroke-width="2"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg> VERIFY &amp; ENABLE`;
    }
  }
}

async function disable2FA() {
  if (!confirm('Disable 2FA? Your account will only be protected by password after this.')) return;
  try {
    const d = await (await fetch(`${API}/api/2fa/disable`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username: me.username })
    })).json();
    if (d.success) {
      toast('2FA DISABLED', 'warn');
      const steps = document.getElementById('tfaSteps');
      if (steps) steps.style.display = '';
      load2FAStatus();
    } else {
      toast(d.error || 'DISABLE FAILED', 'error');
    }
  } catch(e) {
    toast('ERROR', 'error');
  }
}

async function loadAudit(){
  try{const rows=await(await fetch(`${API}/api/audit`)).json();
    const tb=document.getElementById('auditBody');tb.innerHTML='';
    rows.forEach(e=>{const tr=document.createElement('tr');tr.innerHTML=`<td style="font-family:'JetBrains Mono',monospace;color:var(--muted)">${e.id}</td><td style="font-family:'JetBrains Mono',monospace;font-weight:700;color:var(--text)">${e.username}</td><td><span class="apill ${e.action}">${e.action}</span></td><td style="font-size:10px;color:var(--muted);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:'JetBrains Mono',monospace">${e.details||'—'}</td><td style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--muted)">${e.ip_addr||'—'}</td><td style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--muted)">${new Date(e.logged_at).toLocaleString()}</td><td class="a-hash">${e.integrity}</td>`;tb.appendChild(tr);});
  }catch{}
}

function toast(msg,type='info'){
  const w=document.getElementById('ta'),el=document.createElement('div');
  el.className='toast '+type;
  const icons={success:'✓',error:'✕',info:'›',warn:'⚠'};
  el.innerHTML=`<span style="font-size:14px;flex-shrink:0">${icons[type]||'·'}</span><span>${msg}</span>`;
  w.appendChild(el);setTimeout(()=>el.remove(),3800);
}

/* ── SENT MESSAGES ─────────────────────────────────────────────────── */
async function loadSent(){
  try{const msgs=await(await fetch(`${API}/api/messages/sent?username=${me.username}`)).json();
    const list=document.getElementById('sentList');list.innerHTML='';
    if(!msgs.length){list.innerHTML='<div class="empty-st">// outbox empty</div>';return;}
    msgs.forEach(m=>{
      const row=document.createElement('div');row.className='irow-sent';
      const cat=m.category||'general';
      const hasAtt=m.has_attachment?`<span class="cpill general" style="color:var(--c3)">📎</span>`:'—';
      row.innerHTML=`<div class="i-num">#${m.id}</div><div class="i-from">${m.recipient}</div><div><span class="cpill ${cat}">${cat}</span></div><div class="i-time">${new Date(m.sent_at).toLocaleString()}</div><div>${hasAtt}</div>`;
      list.appendChild(row);
    });
  }catch{}
}

/* ── KEY MANAGER ────────────────────────────────────────────────────── */
async function loadKeys(){
  try{const keys=await(await fetch(`${API}/api/keys`)).json();
    const g=document.getElementById('keyGrid');g.innerHTML='';
    keys.forEach(k=>{
      const c=document.createElement('div');c.className='key-card';
      c.innerHTML=`<div class="${k.is_active?'key-active-pill':'key-retired-pill'}">${k.is_active?'● ACTIVE':'○ RETIRED'}</div><div class="key-card-name">${k.key_name}</div><div class="key-card-meta">ID: ${k.id}<br>Created: ${new Date(k.created_at).toLocaleString()}<br>By: ${k.created_by}${k.rotated_at?'<br>Rotated: '+new Date(k.rotated_at).toLocaleString():''}</div>`;
      g.appendChild(c);
    });
  }catch{}
}
async function rotateKey(){
  if(!confirm('Rotate encryption key? Old key is kept for decrypting historical messages.'))return;
  try{const d=await(await fetch(`${API}/api/keys/rotate`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:me.username})})).json();
    if(d.success){toast('KEY ROTATED — old key preserved for decryption','success');loadKeys();}
    else toast(d.error||'ROTATION FAILED','error');
  }catch{toast('ERROR','error');}
}
async function genAndShareKey(){
  try{const d=await(await fetch(`${API}/api/keys/generate`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:me.username})})).json();
    document.getElementById('genKeyOut').value=d.key;toast('KEY GENERATED — copy it now','info');
  }catch{toast('ERROR','error');}
}
async function doShareKey(){
  const toUser=document.getElementById('shareToUser').value;
  const keyData=document.getElementById('genKeyOut').value.trim();
  const keyName=document.getElementById('shareKeyName').value.trim()||'shared-key';
  if(!toUser||!keyData){toast('SELECT USER AND GENERATE A KEY FIRST','error');return;}
  try{const d=await(await fetch(`${API}/api/keys/share`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({from_user:me.username,to_user:toUser,key_data:keyData,key_name:keyName})})).json();
    if(d.success){toast(`KEY SHARED WITH ${toUser}`,'success');loadSharedKeys();}else toast(d.error||'FAILED','error');
  }catch{toast('ERROR','error');}
}
async function loadSharedKeys(){
  try{const keys=await(await fetch(`${API}/api/keys/shared?username=${me.username}`)).json();
    const el=document.getElementById('sharedKeysList');el.innerHTML='';
    if(!keys.length){el.innerHTML='<div class="empty-st" style="padding:14px">// no keys shared with you</div>';return;}
    keys.forEach(k=>{
      const row=document.createElement('div');row.className='sk-row';
      const acc=k.accepted?'<span class="kstatus active">ACCEPTED</span>':'<button class="btn btn-c4" style="font-size:9px;padding:5px 10px" onclick="acceptSharedKey('+k.id+')">ACCEPT</button>';
      row.innerHTML=`<div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text)">${k.key_name} <span style="color:var(--muted)">from ${k.from_user}</span></div><div>${acc}</div><div style="font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--muted)">${new Date(k.shared_at).toLocaleDateString()}</div><div></div>`;
      el.appendChild(row);
    });
  }catch{}
}
async function acceptSharedKey(id){
  try{await fetch(`${API}/api/keys/shared/accept`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({share_id:id})});toast('KEY ACCEPTED','success');loadSharedKeys();}catch{toast('ERROR','error');}
}

/* ── USER MANAGER ───────────────────────────────────────────────────── */
async function loadAllUsers(){
  try{const users=await(await fetch(`${API}/api/users/all`)).json();
    const el=document.getElementById('userMgrList');el.innerHTML='';
    if(!users.length){el.innerHTML='<div class="empty-st">// no users</div>';return;}
    users.forEach(u=>{
      if(u.username===me.username)return;
      const row=document.createElement('div');row.className='usr-row';
      const roleOpts=['admin','cashier','customer_support','user'].map(r=>`<option value="${r}" ${r===u.role?'selected':''}>${r}</option>`).join('');
      const tfa=u.totp_enabled?'<span style="color:var(--c2);font-size:10px;font-family:monospace">ON</span>':'<span style="color:var(--muted);font-size:10px;font-family:monospace">OFF</span>';
      row.innerHTML=`<div style="font-weight:700;color:var(--white);font-family:'Orbitron',monospace;font-size:11px">${u.username}</div>
        <div><select class="ifield" style="padding:5px 8px;font-size:11px" onchange="changeRole('${u.username}',this.value)">${roleOpts}</select></div>
        <div>${tfa}</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--muted)">${u.created_at?new Date(u.created_at).toLocaleDateString():'-'}</div>
        <div><button class="btn btn-red" style="font-size:9px;padding:5px 10px" onclick="deleteUser('${u.username}')">DELETE</button></div>`;
      el.appendChild(row);
    });
  }catch{}
}
async function changeRole(username,role){
  try{const d=await(await fetch(`${API}/api/users/role`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({admin:me.username,username,role})})).json();
    if(d.success)toast(`${username} role → ${role}`,'success');else toast(d.error||'FAILED','error');
  }catch{toast('ERROR','error');}
}
async function deleteUser(username){
  if(!confirm(`Delete user "${username}"? This cannot be undone.`))return;
  try{const d=await(await fetch(`${API}/api/users/delete`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({admin:me.username,username})})).json();
    if(d.success){toast(`${username} DELETED`,'warn');loadAllUsers();}else toast(d.error||'FAILED','error');
  }catch{toast('ERROR','error');}
}


/* ══════════════════════════════════════════════════════════════
   KEY SHARING MODULE
══════════════════════════════════════════════════════════════ */
let _ksGeneratedKey = null;
let _ksTab = 'gen';

function ksSetTab(tab) {
  _ksTab = tab;
  document.getElementById('ksTabGen').classList.toggle('on', tab === 'gen');
  const sysTab = document.getElementById('ksTabSysBtn') || document.getElementById('ksTabSys');
  if (sysTab) sysTab.classList.toggle('on', tab === 'sys');
  document.getElementById('ksGenPanel').style.display = tab === 'gen' ? '' : 'none';
  const sp = document.getElementById('ksSysPanel');
  if (sp) sp.style.display = tab === 'sys' ? '' : 'none';
  ksUpdateStatus();
}

function ksUpdateStatus() {
  const recv = document.getElementById('ksReceiver')?.value || '';
  const line = document.getElementById('ksStatusLine');
  if (!line) return;
  if (!recv) {
    line.textContent = '// select a receiver to continue';
    line.style.color = 'var(--muted)';
  } else if (_ksTab === 'gen' && !_ksGeneratedKey) {
    line.textContent = `// receiver: ${recv} — generate a key to share`;
    line.style.color = 'var(--muted)';
  } else if (_ksTab === 'gen' && _ksGeneratedKey) {
    const name = document.getElementById('ksKeyName')?.value || 'shared-key';
    line.textContent = `// ready to share "${name}" → ${recv}`;
    line.style.color = 'var(--c2)';
  } else {
    line.textContent = `// receiver: ${recv} — select system key`;
    line.style.color = 'var(--muted)';
  }
}

async function ksGenerateKey() {
  try {
    const d = await (await fetch(`${API}/api/keys/generate`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username: me.username })
    })).json();
    _ksGeneratedKey = d.key;
    document.getElementById('ksKeyValue').textContent = d.key;
    document.getElementById('ksKeyPreview').style.display = '';
    toast('KEY GENERATED — copy for your records', 'info');
    ksUpdateStatus();
  } catch { toast('ERROR GENERATING KEY', 'error'); }
}

function ksSelectAll(el) {
  const sel = window.getSelection();
  const range = document.createRange();
  range.selectNodeContents(el);
  sel.removeAllRanges();
  sel.addRange(range);
  document.execCommand('copy');
  toast('KEY COPIED TO CLIPBOARD', 'success');
}

async function ksDoShare() {
  const toUser = document.getElementById('ksReceiver')?.value;
  if (!toUser) { toast('SELECT A RECEIVER FIRST', 'error'); return; }

  let payload = { from_user: me.username, to_user: toUser };

  if (_ksTab === 'gen') {
    if (!_ksGeneratedKey) { toast('GENERATE A KEY FIRST', 'error'); return; }
    const keyName = document.getElementById('ksKeyName')?.value.trim() || 'shared-key';
    payload.key_data = _ksGeneratedKey;
    payload.key_name = keyName;
  } else {
    const sysId = document.getElementById('ksSysKeyId')?.value;
    if (!sysId) { toast('SELECT A SYSTEM KEY', 'error'); return; }
    payload.enc_key_id = parseInt(sysId);
  }

  try {
    const d = await (await fetch(`${API}/api/keys/share`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    })).json();
    if (d.success) {
      toast(d.message || `KEY SHARED WITH ${toUser}`, 'success');
      _ksGeneratedKey = null;
      document.getElementById('ksKeyPreview').style.display = 'none';
      document.getElementById('ksKeyName').value = 'shared-key';
      document.getElementById('ksReceiver').value = '';
      ksUpdateStatus();
      ksLoadOutgoing();
    } else {
      toast(d.error || 'SHARE FAILED', 'error');
    }
  } catch { toast('NETWORK ERROR', 'error'); }
}

async function ksLoadIncoming() {
  try {
    const keys = await (await fetch(`${API}/api/keys/shared?username=${me.username}`)).json();
    const el = document.getElementById('ksIncoming');
    if (!el) return;

    // Update badge
    const pending = keys.filter(k => !k.accepted).length;
    const badge = document.getElementById('keyShareBadge');
    if (badge) {
      if (pending > 0) { badge.textContent = pending; badge.style.display = 'inline'; }
      else badge.style.display = 'none';
    }

    if (!keys.length) {
      el.innerHTML = '<div class="empty-st" style="padding:14px">// no keys shared with you yet</div>';
      return;
    }
    el.innerHTML = '';
    keys.forEach(k => {
      const row = document.createElement('div');
      row.className = 'ks-row ks-row-5';
      const accepted = k.accepted;
      const statusCell = accepted
        ? `<span class="kstatus-accepted">✓ ACCEPTED</span>`
        : `<button class="btn-accept-key" onclick="ksAcceptKey(${k.id}, this)">ACCEPT KEY</button>`;
      row.innerHTML = `
        <div>
          <div class="ks-row-name">${k.key_name}</div>
        </div>
        <div class="ks-row-user">${k.from_user}</div>
        <div class="ks-row-time">${new Date(k.shared_at).toLocaleDateString()}<br>${new Date(k.shared_at).toLocaleTimeString()}</div>
        <div>${statusCell}</div>
        <div><button class="btn-ks-delete" onclick="ksDeleteSharedKey(${k.id}, this)" title="Delete this key"><svg width="12" height="12" viewBox="0 0 24 24" fill="none"><polyline points="3,6 5,6 21,6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M10 11v6M14 11v6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M9 6V4a1 1 0 011-1h4a1 1 0 011 1v2" stroke="currentColor" stroke-width="2"/></svg></button></div>
      `;
      el.appendChild(row);
    });

    // Populate decrypt dropdown with accepted keys
    const decSel = document.getElementById('ksDecryptKeyId');
    if (decSel) {
      const prev = decSel.value;
      decSel.innerHTML = '<option value="">-- select an accepted key --</option>';
      keys.filter(k => k.accepted).forEach(k => {
        const o = document.createElement('option');
        o.value = k.id;
        o.textContent = `${k.key_name} (from ${k.from_user})`;
        decSel.appendChild(o);
      });
      if (prev) decSel.value = prev;
      // Show decrypt panel if any accepted keys
      const dp = document.getElementById('ksDecryptPanel');
      if (dp) dp.style.display = keys.some(k => k.accepted) ? '' : 'none';
    }
  } catch {}
}

async function ksLoadOutgoing() {
  try {
    const keys = await (await fetch(`${API}/api/keys/shared/outgoing?username=${me.username}`)).json();
    const el = document.getElementById('ksOutgoing');
    if (!el) return;
    if (!keys.length) {
      el.innerHTML = '<div class="empty-st" style="padding:14px">// you have not shared any keys yet</div>';
      return;
    }
    el.innerHTML = '';
    keys.forEach(k => {
      const row = document.createElement('div');
      row.className = 'ks-row ks-row-5';
      const statusCell = k.accepted
        ? `<span class="kstatus-accepted">✓ ACCEPTED</span>`
        : `<span class="kstatus-pending">⏳ PENDING</span>`;
      row.innerHTML = `
        <div>
          <div class="ks-row-name">${k.key_name}</div>
        </div>
        <div class="ks-row-user">${k.to_user}</div>
        <div class="ks-row-time">${new Date(k.shared_at).toLocaleDateString()}<br>${new Date(k.shared_at).toLocaleTimeString()}</div>
        <div>${statusCell}</div>
        <div><button class="btn-ks-delete" onclick="ksDeleteSharedKey(${k.id}, this)" title="Revoke this shared key"><svg width="12" height="12" viewBox="0 0 24 24" fill="none"><polyline points="3,6 5,6 21,6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M10 11v6M14 11v6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M9 6V4a1 1 0 011-1h4a1 1 0 011 1v2" stroke="currentColor" stroke-width="2"/></svg></button></div>
      `;
      el.appendChild(row);
    });
  } catch {}
}

async function ksAcceptKey(id, btn) {
  btn.disabled = true;
  btn.textContent = 'ACCEPTING...';
  try {
    const d = await (await fetch(`${API}/api/keys/shared/accept`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ share_id: id, username: me.username })
    })).json();
    if (d.success) {
      toast(d.message || 'KEY ACCEPTED — you can now use it to decrypt', 'success');
      ksLoadIncoming();
    } else {
      toast(d.error || 'FAILED', 'error');
      btn.disabled = false; btn.textContent = 'ACCEPT KEY';
    }
  } catch {
    toast('ERROR', 'error');
    btn.disabled = false; btn.textContent = 'ACCEPT KEY';
  }
}

async function ksDecryptMsg() {
  const shareId = document.getElementById('ksDecryptKeyId')?.value;
  const cipher  = document.getElementById('ksDecryptCipher')?.value.trim();
  const out     = document.getElementById('ksDecryptResult');
  const st      = document.getElementById('ksDecStatus');
  if (!shareId) { toast('SELECT A SHARED KEY', 'error'); return; }
  if (!cipher)  { toast('PASTE OR LOAD A CIPHERTEXT FIRST', 'error'); return; }
  if (out) out.textContent = '// decrypting...';
  if (st)  { st.textContent='// working...'; st.style.color='var(--muted)'; }
  try {
    const payload = { username: me.username, share_id: parseInt(shareId), ciphertext: cipher };
    if (window._ksMsgId) payload.message_id = window._ksMsgId;
    const d = await (await fetch(`${API}/api/keys/shared/decrypt`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    })).json();
    if (d.success) {
      if (out) { out.textContent = d.plaintext; out.style.color='var(--c2)'; }
      if (st)  { st.innerHTML='<span style="color:var(--c2)">✓ DECRYPTION OK · KEY: '+d.key_name+'</span>'; }
      toast('DECRYPTION SUCCESSFUL', 'success');
    } else {
      if (out) { out.textContent = `// error: ${d.error}`; out.style.color='var(--danger)'; }
      if (st)  { st.innerHTML='<span style="color:var(--danger)">✕ '+( d.error||'failed')+'</span>'; }
      toast(d.error || 'DECRYPTION FAILED', 'error');
    }
  } catch {
    if (out) out.textContent = '// network error';
    toast('NETWORK ERROR', 'error');
  }
}

async function ksLoadReceiversDropdown() {
  try {
    const users = await (await fetch(`${API}/api/users`)).json();
    const sel = document.getElementById('ksReceiver');
    if (!sel) return;
    sel.innerHTML = '<option value="">-- select user --</option>';
    users.forEach(u => {
      if (u.username !== me.username) {
        const o = document.createElement('option');
        o.value = u.username;
        o.textContent = `${u.username}  [${(u.role||'').replace('_',' ').toUpperCase()}]`;
        sel.appendChild(o);
      }
    });
  } catch {}
}

async function ksLoadSystemKeys() {
  if (me.role !== 'admin') return;
  // Show admin system key tab
  const sysTab = document.getElementById('ksTabSys');
  if (sysTab) sysTab.style.display = '';
  try {
    const keys = await (await fetch(`${API}/api/keys`)).json();
    const sel = document.getElementById('ksSysKeyId');
    if (!sel) return;
    sel.innerHTML = '<option value="">-- select system key --</option>';
    keys.forEach(k => {
      const o = document.createElement('option');
      o.value = k.id;
      o.textContent = `${k.key_name} [${k.is_active ? '● ACTIVE' : '○ RETIRED'}] — ID:${k.id}`;
      sel.appendChild(o);
    });
  } catch {}
}

async function loadKeySharePage() {
  await Promise.all([
    ksLoadReceiversDropdown(),
    ksLoadIncoming(),
    ksLoadOutgoing(),
    ksLoadSystemKeys()
  ]);
  ksUpdateStatus();
}

function ksOpenWithMsg(msgId, cipherPreview, sender, sentAt, category) {
  // Navigate to key sharing section and pre-fill the decrypt panel
  goS('keyshare');
  // Store the message id so decrypt can send it to the backend
  window._ksMsgId = msgId;
  // Get full ciphertext from stored map
  const fullCipher = (window._inboxCiphertextMap && window._inboxCiphertextMap[msgId])
    ? window._inboxCiphertextMap[msgId]
    : cipherPreview;
  // Fill the ciphertext textarea
  const ta = document.getElementById('ksDecryptCipher');
  if (ta) { ta.value = fullCipher; }
  // Show the source message info strip
  const strip = document.getElementById('ksMsgSource');
  const stripTxt = document.getElementById('ksMsgSourceText');
  if (strip && stripTxt) {
    stripTxt.innerHTML = `MSG #${msgId} · From: <b>${sender}</b> · <span class="cpill ${category}" style="font-size:9px;padding:2px 7px">${category}</span> · ${sentAt}`;
    strip.style.display = '';
  }
  // Update the cipher source indicator
  const ind = document.getElementById('ksCipherSrcLabel');
  if (ind) { ind.textContent = `// from MSG #${msgId} (${sender})`; ind.style.color = 'var(--c2)'; }
  const indWrap = document.getElementById('ksCipherSrcInd');
  if (indWrap) indWrap.classList.add('has-source');
  // Show the decrypt panel
  const dp = document.getElementById('ksDecryptPanel');
  if (dp) dp.style.display = '';
  // Scroll into decrypt panel
  setTimeout(()=>{ dp && dp.scrollIntoView({behavior:'smooth',block:'start'}); }, 180);
}

function ksClearMsgSource() {
  const strip = document.getElementById('ksMsgSource');
  if (strip) strip.style.display = 'none';
  const ind = document.getElementById('ksCipherSrcLabel');
  if (ind) { ind.textContent = '// no message selected'; ind.style.color = ''; }
  const indWrap = document.getElementById('ksCipherSrcInd');
  if (indWrap) indWrap.classList.remove('has-source');
}

function ksOnCipherInput() {
  const ta = document.getElementById('ksDecryptCipher');
  const ind = document.getElementById('ksCipherSrcLabel');
  if (!ta || !ind) return;
  if (ta.value.trim() && !document.getElementById('ksMsgSource')?.style.display === 'none') {
    // If user manually typed, update indicator
    if (!document.getElementById('ksMsgSource') || document.getElementById('ksMsgSource').style.display === 'none') {
      ind.textContent = '// manually entered';
      ind.style.color = 'var(--c5)';
    }
  } else if (!ta.value.trim()) {
    ksClearMsgSource();
  }
}


async function ksDeleteSharedKey(id, btn) {
  if (!confirm('Delete this shared key? This cannot be undone.')) return;
  btn.disabled = true;
  const row = btn.closest('.ks-row');
  if (row) row.style.opacity = '0.4';
  try {
    const d = await (await fetch(`${API}/api/keys/shared/delete`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ share_id: id, username: me.username })
    })).json();
    if (d.success) {
      toast('SHARED KEY DELETED', 'warn');
      // Reload both panels
      ksLoadIncoming();
      ksLoadOutgoing();
    } else {
      toast(d.error || 'DELETE FAILED', 'error');
      btn.disabled = false;
      if (row) row.style.opacity = '1';
    }
  } catch {
    toast('NETWORK ERROR', 'error');
    btn.disabled = false;
    if (row) row.style.opacity = '1';
  }
}

function ksClearDecrypt() {
  const ta = document.getElementById('ksDecryptCipher');
  if (ta) ta.value = '';
  const res = document.getElementById('ksDecryptResult');
  if (res) res.textContent = '// awaiting decryption...';
  const st = document.getElementById('ksDecStatus');
  if (st) st.textContent = '';
  window._ksMsgId = null;
  ksClearMsgSource();
}

/* ═══════════════════════════════════════════════════════
   ENCRYPTED GROUP MESSAGING
═══════════════════════════════════════════════════════ */

let _activeGroupId   = null;
let _activeGroupName = '';
let _grpPollTimer    = null;

// ── Load groups list ───────────────────────────────────────────────────────
async function loadGroups() {
  try {
    const groups = await (await fetch(`${API}/api/groups?username=${me.username}`)).json();
    const el = document.getElementById('grpList');
    if (!el) return;

    if (!groups.length) {
      el.innerHTML = '<div class="empty-st">// you have not joined any groups yet — create one above</div>';
      return;
    }
    el.innerHTML = '';
    groups.forEach(g => {
      const row = document.createElement('div');
      row.className = 'grp-list-row';
      const isCreator = g.created_by === me.username;
      row.innerHTML = `
        <div class="grp-id">#${g.id}</div>
        <div>
          <div class="grp-name">${g.group_name}</div>
          ${isCreator ? '<span class="grp-creator-badge">CREATOR</span>' : ''}
        </div>
        <div class="grp-meta">${g.created_by}</div>
        <div class="grp-meta">${g.member_count} members</div>
        <div class="grp-meta">${g.message_count} msgs</div>
        <div style="display:flex;gap:6px">
          <button class="btn-grp-open" onclick="openGroupChat(${g.id}, '${g.group_name.replace(/'/g,"\'")}')">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
            OPEN CHAT
          </button>
        </div>
      `;
      el.appendChild(row);
    });
  } catch(e) { console.error(e); }
}

// ── Tag-based member picker ────────────────────────────────────────────────
let _grpAllUsers = [];       // [{username, role}, ...]
let _grpSelected = new Set(); // currently selected usernames

function _renderTagPicker() {
  const selectedEl  = document.getElementById('grpTagSelected');
  const dropdownEl  = document.getElementById('grpTagDropdown');
  const hiddenSel   = document.getElementById('grpMembers');
  if (!selectedEl || !dropdownEl || !hiddenSel) return;

  // Render selected tags
  if (_grpSelected.size === 0) {
    selectedEl.innerHTML = '<span class="grp-tag-placeholder">// no members added yet — click a name below</span>';
  } else {
    selectedEl.innerHTML = [..._grpSelected].map(u => `
      <span class="grp-member-tag">
        ${u}
        <span class="tag-remove" onclick="grpTagRemove('${u}')">✕</span>
      </span>
    `).join('');
  }

  // Render dropdown options
  dropdownEl.innerHTML = _grpAllUsers
    .filter(u => u.username !== me.username)
    .map(u => {
      const sel = _grpSelected.has(u.username);
      return `<div class="grp-tag-option${sel?' selected':''}" onclick="${sel?'':'grpTagAdd(\''+u.username+'\')'}">
        <span>${u.username}</span>
        <span style="display:flex;align-items:center;gap:8px">
          <span class="opt-role">${(u.role||'user').replace('_',' ').toUpperCase()}</span>
          ${sel ? '<span style="color:var(--c2);font-size:10px">✓</span>' : '<span class="opt-add-ico">+</span>'}
        </span>
      </div>`;
    }).join('');

  // Sync hidden <select> so createGroup() reads selected values
  hiddenSel.innerHTML = '';
  _grpAllUsers.forEach(u => {
    const o = document.createElement('option');
    o.value = u.username;
    o.selected = _grpSelected.has(u.username);
    hiddenSel.appendChild(o);
  });
}

function grpTagAdd(username) {
  _grpSelected.add(username);
  _renderTagPicker();
}
function grpTagRemove(username) {
  _grpSelected.delete(username);
  _renderTagPicker();
}

// ── Load users into create-group member picker ─────────────────────────────
async function loadGroupMembersDropdown() {
  try {
    _grpAllUsers = await (await fetch(`${API}/api/users`)).json();
    _grpSelected.clear();
    _renderTagPicker();
  } catch {}
}

// ── Create a new group ─────────────────────────────────────────────────────
async function createGroup() {
  const name    = document.getElementById('grpName')?.value.trim();
  const selEl   = document.getElementById('grpMembers');
  const members = selEl ? [...selEl.selectedOptions].map(o => o.value) : [];
  const st      = document.getElementById('grpCreateStatus');

  if (!name) { toast('ENTER A GROUP NAME', 'error'); return; }

  if (st) { st.textContent = '// creating...'; st.style.color = 'var(--muted)'; }
  try {
    const d = await (await fetch(`${API}/api/groups/create`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username: me.username, group_name: name, members })
    })).json();

    if (d.success) {
      toast(`GROUP "${d.group_name}" CREATED — AES ENCRYPTED`, 'success');
      if (st) { st.textContent = `✓ group #${d.group_id} created`; st.style.color = 'var(--c2)'; }
      document.getElementById('grpName').value = '';
      if (selEl) { [...selEl.options].forEach(o => o.selected = false); }
      loadGroups();
      setTimeout(() => { if(st) st.textContent = ''; }, 3000);
    } else {
      if (st) { st.textContent = `✕ ${d.error}`; st.style.color = 'var(--danger)'; }
      toast(d.error || 'CREATE FAILED', 'error');
    }
  } catch {
    toast('NETWORK ERROR', 'error');
    if (st) st.textContent = '';
  }
}

// ── Open group chat ────────────────────────────────────────────────────────
async function openGroupChat(groupId, groupName) {
  _activeGroupId   = groupId;
  _activeGroupName = groupName;

  document.getElementById('grpChatTitle').textContent = `// ${groupName.toUpperCase()} — ENCRYPTED CHAT`;
  document.getElementById('grpChatPanel').style.display = '';
  document.getElementById('grpMgrPanel').style.display = 'none';
  _updateGrpMgrVisibility();

  // Scroll to chat
  setTimeout(() => {
    document.getElementById('grpChatPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 100);

  await Promise.all([loadGroupMessages(), loadGroupManagementPanel()]);

  // Start polling for new messages
  if (_grpPollTimer) clearInterval(_grpPollTimer);
  _grpPollTimer = setInterval(() => {
    if (_activeGroupId) loadGroupMessages();
  }, 4000);
}

function closeGroupChat() {
  _activeGroupId = null;
  document.getElementById('grpChatPanel').style.display = 'none';
  if (_grpPollTimer) { clearInterval(_grpPollTimer); _grpPollTimer = null; }
}

// ── Load messages into chat zone ───────────────────────────────────────────
async function loadGroupMessages() {
  if (!_activeGroupId) return;
  try {
    const msgs = await (await fetch(
      `${API}/api/groups/${_activeGroupId}/messages?username=${me.username}`
    )).json();

    const zone = document.getElementById('grpMessages');
    if (!zone) return;

    if (msgs.error) {
      zone.innerHTML = `<div class="empty-st" style="color:var(--danger)">${msgs.error}</div>`;
      return;
    }
    if (!msgs.length) {
      zone.innerHTML = '<div class="empty-st">// no messages yet — send the first encrypted message</div>';
      return;
    }

    // Preserve scroll position at bottom
    const wasAtBottom = zone.scrollHeight - zone.scrollTop - zone.clientHeight < 40;

    zone.innerHTML = '';
    msgs.forEach(m => {
      const isMe = m.sender === me.username;
      const bubble = document.createElement('div');
      bubble.className = 'grp-bubble ' + (isMe ? 'grp-bubble-me' : 'grp-bubble-them');
      const t = new Date(m.sent_at);
      const timeStr = t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const intBadge = m.integrity === 'PASS'
        ? '<span class="grp-int-ok">✓ HMAC</span>'
        : '<span class="grp-int-fail">⚠ TAMPERED</span>';
      const attHTML = m.has_attachment && m.attachment ? _grpRenderAttachment(m.attachment) : '';
      bubble.innerHTML = `
        ${!isMe ? `<div class="grp-bubble-sender">${m.sender}</div>` : ''}
        <div class="grp-bubble-text">${m.plaintext}</div>
        ${attHTML}
        <div class="grp-bubble-meta">${timeStr} ${intBadge}${m.has_attachment ? ' <span style="color:var(--c3);font-size:8px">📎 ENC</span>' : ''}</div>
      `;
      zone.appendChild(bubble);
    });

    if (wasAtBottom || zone.children.length <= 2) {
      zone.scrollTop = zone.scrollHeight;
    }
  } catch(e) { console.error(e); }
}

// ── Send a message ─────────────────────────────────────────────────────────
async function sendGroupMessage() {
  const input   = document.getElementById('grpMsgInput');
  const content = input?.value.trim() || (_grpAttachFile ? '📎 ' + _grpAttachFile.name : '');
  if (!content && !_grpAttachFile) return;
  if (!_activeGroupId) { toast('NO ACTIVE GROUP', 'error'); return; }

  input.disabled = true;
  let attachment = null;
  if (_grpAttachFile) {
    try {
      const b64 = await new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(r.result.split(',')[1]);r.onerror=rej;r.readAsDataURL(_grpAttachFile);});
      attachment = { name: _grpAttachFile.name, mime: _grpAttachFile.type||'application/octet-stream', data_b64: b64 };
    } catch { toast('ATTACHMENT READ ERROR','error'); input.disabled=false; return; }
  }

  try {
    const body = { username: me.username, content: content || '📎 ' + (attachment?.name||'file') };
    if (attachment) body.attachment = attachment;
    const d = await (await fetch(`${API}/api/groups/${_activeGroupId}/send`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    })).json();

    if (d.success) {
      input.value = '';
      clearGrpAttachment();
      await loadGroupMessages();
    } else {
      toast(d.error || 'SEND FAILED', 'error');
    }
  } catch { toast('NETWORK ERROR', 'error'); }
  finally { input.disabled = false; input.focus(); }
}

// ── Management panel (members + controls) ─────────────────────────────────
function toggleGrpMgr() {
  const p = document.getElementById('grpMgrPanel');
  if (p) p.style.display = p.style.display === 'none' ? '' : 'none';
}

function _updateGrpMgrVisibility(creatorName) {
  // Only admin can see the manage button
  const mgrBtn = document.getElementById('grpMgrToggle');
  if (mgrBtn) {
    mgrBtn.style.display = me.role === 'admin' ? '' : 'none';
  }
}

async function loadGroupManagementPanel() {
  if (!_activeGroupId) return;
  try {
    const d = await (await fetch(
      `${API}/api/groups/${_activeGroupId}?username=${me.username}`
    )).json();

    if (d.error) return;

    // Member list display
    const ml = document.getElementById('grpMemberList');
    if (ml) {
      ml.innerHTML = d.members.map(m => `
        <div class="grp-member-item">
          <span class="grp-member-dot ${m.username === d.group.created_by ? 'creator' : ''}"></span>
          ${m.username}
          ${m.username === d.group.created_by ? ' <span style="color:var(--c5);font-size:8px">CREATOR</span>' : ''}
        </div>
      `).join('');
    }

    // Populate add/remove dropdowns with all users / current members
    const allUsers = await (await fetch(`${API}/api/users`)).json();
    const memberNames = new Set(d.members.map(m => m.username));
    const creator = d.group.created_by;

    const addSel = document.getElementById('grpAddUser');
    if (addSel) {
      addSel.innerHTML = '<option value="">-- select user --</option>';
      allUsers.forEach(u => {
        if (!memberNames.has(u.username)) {
          const o = document.createElement('option');
          o.value = u.username;
          o.textContent = `${u.username} [${(u.role||'user').replace('_',' ').toUpperCase()}]`;
          addSel.appendChild(o);
        }
      });
    }

    const remSel = document.getElementById('grpRemoveUser');
    if (remSel) {
      remSel.innerHTML = '<option value="">-- select member --</option>';
      d.members.forEach(m => {
        if (m.username !== creator) {
          const o = document.createElement('option');
          o.value = m.username;
          o.textContent = m.username;
          remSel.appendChild(o);
        }
      });
    }
  } catch(e) { console.error(e); }
}

async function addGroupMember() {
  const user = document.getElementById('grpAddUser')?.value;
  if (!user) { toast('SELECT A USER TO ADD', 'error'); return; }
  const st = document.getElementById('grpMgrStatus');
  if (st) { st.textContent = '// adding...'; st.style.color = 'var(--muted)'; }
  try {
    const d = await (await fetch(`${API}/api/groups/${_activeGroupId}/members/add`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username: me.username, new_member: user })
    })).json();
    if (d.success) {
      toast(`${user} ADDED TO GROUP`, 'success');
      if (st) { st.textContent = `✓ ${user} added`; st.style.color = 'var(--c2)'; }
      await loadGroupManagementPanel();
      loadGroups();
    } else {
      toast(d.error || 'ADD FAILED', 'error');
      if (st) { st.textContent = `✕ ${d.error}`; st.style.color = 'var(--danger)'; }
    }
  } catch { toast('NETWORK ERROR', 'error'); }
}

async function removeGroupMember() {
  const user = document.getElementById('grpRemoveUser')?.value;
  if (!user) { toast('SELECT A MEMBER TO REMOVE', 'error'); return; }
  if (!confirm(`Remove ${user} from group? The group encryption key will be rotated.`)) return;
  const st = document.getElementById('grpMgrStatus');
  if (st) { st.textContent = '// removing + rotating key...'; st.style.color = 'var(--muted)'; }
  try {
    const d = await (await fetch(`${API}/api/groups/${_activeGroupId}/members/remove`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username: me.username, remove_member: user })
    })).json();
    if (d.success) {
      toast(`${user} REMOVED — KEY ROTATED`, 'warn');
      if (st) { st.textContent = `✓ ${user} removed · key rotated`; st.style.color = 'var(--c5)'; }
      await loadGroupManagementPanel();
      loadGroups();
    } else {
      toast(d.error || 'REMOVE FAILED', 'error');
      if (st) { st.textContent = `✕ ${d.error}`; st.style.color = 'var(--danger)'; }
    }
  } catch { toast('NETWORK ERROR', 'error'); }
}

async function deleteGroup() {
  if (!_activeGroupId) return;
  if (!confirm(`Permanently delete "${_activeGroupName}"? All messages will be lost.`)) return;
  try {
    const d = await (await fetch(`${API}/api/groups/${_activeGroupId}/delete`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username: me.username })
    })).json();
    if (d.success) {
      toast('GROUP DELETED', 'warn');
      closeGroupChat();
      loadGroups();
    } else {
      toast(d.error || 'DELETE FAILED', 'error');
    }
  } catch { toast('NETWORK ERROR', 'error'); }
}

async function leaveGroup() {
  if (!_activeGroupId) return;
  if (!confirm(`Leave "${_activeGroupName}"? The group key will be rotated.`)) return;
  try {
    const d = await (await fetch(`${API}/api/groups/${_activeGroupId}/leave`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username: me.username })
    })).json();
    if (d.success) {
      toast('LEFT GROUP — KEY ROTATED', 'warn');
      closeGroupChat();
      loadGroups();
    } else {
      toast(d.error || 'LEAVE FAILED', 'error');
    }
  } catch { toast('NETWORK ERROR', 'error'); }
}

// ── Group Chat File Attachment ──────────────────────────────────────────────
let _grpAttachFile = null;

function onGrpAttSelect(file) {
  if (!file) return;
  if (file.size > 10 * 1024 * 1024) { toast('GROUP ATTACHMENT MAX 10MB', 'error'); return; }
  _grpAttachFile = file;
  const sz = file.size < 1024 ? file.size + 'B'
           : file.size < 1048576 ? (file.size/1024).toFixed(1) + 'KB'
           : (file.size/1048576).toFixed(1) + 'MB';
  const prev = document.getElementById('grpAttPreview');
  document.getElementById('grpAttName').textContent = '📎 ' + file.name;
  document.getElementById('grpAttSize').textContent = '(' + sz + ')';
  if (prev) prev.style.display = '';
  const btn = document.querySelector('.grp-att-btn');
  if (btn) btn.classList.add('has-file');
  document.getElementById('grpMsgInput').placeholder = '// add a caption (optional)...';
}

function clearGrpAttachment() {
  _grpAttachFile = null;
  const prev = document.getElementById('grpAttPreview');
  if (prev) prev.style.display = 'none';
  const btn = document.querySelector('.grp-att-btn');
  if (btn) btn.classList.remove('has-file');
  document.getElementById('grpAttFileIn').value = '';
  document.getElementById('grpMsgInput').placeholder = '// type encrypted message... (Enter to send)';
}

function _grpRenderAttachment(att) {
  if (!att || att.error) return att?.error ? `<div style="color:var(--danger);font-size:10px">⚠ ${att.error}</div>` : '';
  const mime = att.mime || '';
  const isImg = mime.startsWith('image/');
  const url = `data:${mime};base64,${att.data_b64}`;
  if (isImg) {
    return `<div class="grp-att-block">
      <img src="${url}" alt="${att.name}" onclick="grpDlFile('${url}','${att.name}')">
      <div class="grp-att-file-row" style="padding:6px 10px">
        <span class="grp-att-filename" style="font-size:9px">${att.name}</span>
        <button class="grp-att-dl-btn" onclick="grpDlFile('${url}','${att.name}')">⬇ SAVE</button>
      </div>
    </div>`;
  }
  return `<div class="grp-att-block">
    <div class="grp-att-file-row">
      <div class="grp-att-file-icon">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6z" stroke="currentColor" stroke-width="2"/><polyline points="14,2 14,8 20,8" stroke="currentColor" stroke-width="2"/></svg>
      </div>
      <span class="grp-att-filename">${att.name}</span>
      <button class="grp-att-dl-btn" onclick="grpDlFile('${url}','${att.name}')">⬇ SAVE</button>
    </div>
  </div>`;
}

function grpDlFile(url, name) {
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}