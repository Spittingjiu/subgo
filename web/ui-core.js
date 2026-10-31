'use strict';
// Shared UI primitives. No external requests except the authenticated same-origin API.
const UI = (() => {
  const scopes = new Map();
  let requestSerial = 0, authEpoch = 0, toastTimer = 0;
  const dialogs = [];
  const closeHandlers = new Map();
  let unauthorizedHandler = () => {};
  const $ = s => document.querySelector(s);
  const safeText = value => String(value ?? '').replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s<>"']+/gi, '[地址已隐藏]').replace(/\b(token|password|passwd|authorization|api[_-]?key|secret)\s*[:=]\s*[^\s,;]+/gi, '$1=[已隐藏]');
  function toast(text, kind = '') {
    const el = $('#toastRegion'), label = $('#toastText');
    if (!el || !label) return;
    clearTimeout(toastTimer);
    el.className = 'toast-region' + (kind === 'err' ? ' err' : kind === 'ok' ? ' ok' : '');
    label.textContent = safeText(text);
    toastTimer = setTimeout(dismissToast, kind === 'err' ? 15000 : 8000);
  }
  function dismissToast() { clearTimeout(toastTimer); $('#toastRegion')?.classList.add('hide'); }
  function request(key, context = {}) {
    const old = scopes.get(key); old?.controller.abort();
    const controller = new AbortController(), epoch = authEpoch;
    const handle = { key, serial: ++requestSerial, controller, signal: controller.signal, context: Object.freeze({...context}) };
    handle.current = () => scopes.get(key) === handle && epoch === authEpoch && !controller.signal.aborted;
    scopes.set(key, handle);
    return handle;
  }
  function invalidate(key) { scopes.get(key)?.controller.abort(); scopes.delete(key); }
  function invalidateAll() { ++authEpoch; for (const r of scopes.values()) r.controller.abort(); scopes.clear(); }
  async function api(url, options = {}) {
    const epoch = authEpoch;
    const target = new URL(url, location.origin);
    if (target.origin !== location.origin) throw new Error('管理 API 必须使用本站 origin');
    const method = String(options.method || 'GET').toUpperCase();
    const headers = {'content-type':'application/json', ...(options.headers || {})};
    if (!['GET','HEAD','OPTIONS'].includes(method)) headers['x-requested-with'] = 'XMLHttpRequest';
    const response = await fetch(target.pathname + target.search, {...options, method, headers, credentials:'same-origin'});
    const result = await response.json().catch(() => ({ok:false,error:'服务响应不是有效 JSON'}));
    if (options.signal?.aborted || epoch !== authEpoch) { const error = new Error('请求上下文已取消'); error.name = 'AbortError'; throw error; }
    if (response.status === 401 && target.pathname !== '/api/auth/login') {
      invalidateAll(); unauthorizedHandler();
      const error = new Error('登录已失效，请重新登录'); error.status = 401; throw error;
    }
    if (!response.ok || result.ok !== true) {
      const error = new Error(safeText(result.error || `请求失败（HTTP ${response.status}）`)); error.status = response.status; throw error;
    }
    return result;
  }
  async function download(url, filename, options = {}) {
    const epoch = authEpoch, target = new URL(url, location.origin);
    if (target.origin !== location.origin) throw new Error('下载只能使用本站 origin');
    const response = await fetch(target.pathname + target.search, {credentials:'same-origin',signal:options.signal});
    const checkContext = () => { if (options.signal?.aborted || epoch !== authEpoch) { const error = new Error('下载上下文已取消'); error.name = 'AbortError'; throw error; } };
    checkContext();
    if (response.status === 401) { invalidateAll(); unauthorizedHandler(); const error = new Error('登录已失效，请重新登录'); error.status = 401; throw error; }
    if (!response.ok) throw new Error(`导出失败（HTTP ${response.status}）`);
    const blob = await response.blob(); checkContext();
    const objectURL = URL.createObjectURL(blob), link = document.createElement('a');
    link.href = objectURL; link.download = filename; link.style.display='none';document.body.appendChild(link);link.click();link.remove();
    setTimeout(() => URL.revokeObjectURL(objectURL), 1000);
  }
  function setError(selector, message = '') { const el = $(selector); if (el) el.textContent = safeText(message); }
  function reportError(error, button = null) {
    if (!error || error.name === 'AbortError') return;
    const message = safeText(error.message || error);
    const top = dialogs[dialogs.length - 1];
    const id = top?.id || button?.closest?.('.modal-mask')?.id;
    const local = {subModal:'#modalError',linkModal:'#linkError',addSourceModal:'#addSourceError',cfFilterModal:'#cfFilterError'}[id];
    if (local) setError(local, message);
    toast(message, 'err');
  }
  const actionTriggers = [];
  async function runAction(button, action) {
    if (button?.disabled) return;
    const wasDisabled = !!button?.disabled;
    // Chromium moves focus to BODY when a focused button is disabled. Keep
    // the actual invoking control before applying the temporary busy state.
    const trigger = {button};
    actionTriggers.push(trigger);
    if (button) { button.disabled = true; button.setAttribute('aria-busy','true'); }
    try { return await action(); }
    catch (error) { reportError(error, button); }
    finally {
      const index = actionTriggers.indexOf(trigger);
      if (index >= 0) actionTriggers.splice(index,1);
      if (button) { button.disabled = typeof button._isUnavailable === 'function' ? !!button._isUnavailable() : wasDisabled; button.removeAttribute('aria-busy'); }
    }
  }
  function syncInert() {
    const open = dialogs.length > 0;
    ['#app','#loginCard','#bottomNav'].forEach(s => { const el = $(s); if (el) el.inert = open; });
    document.querySelectorAll('.modal-mask').forEach(el => { el.inert = open && el.id !== dialogs[dialogs.length-1].id; });
  }
  function focusables(mask) {
    return [...mask.querySelectorAll('button:not([disabled]),a[href],input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])')].filter(el => !el.closest('.hide') && el.getAttribute('type') !== 'hidden' && (!el.getClientRects || el.getClientRects().length > 0));
  }
  function openModal(id, initial = '') {
    const mask = $('#'+id); if (!mask) return;
    if (!dialogs.some(d => d.id === id)) {
      const focused = document.activeElement;
      const invoker = actionTriggers[actionTriggers.length-1]?.button;
      const returnTo = focused && focused !== document.body && focused !== document.documentElement && !focused.disabled ? focused : invoker || focused;
      dialogs.push({id, returnTo});
    }
    mask.classList.remove('hide'); syncInert();
    const target = (initial && mask.querySelector(initial)) || focusables(mask)[0] || mask.querySelector('.modal-box');
    target?.focus();
  }
  function closeModal(id) {
    const index = dialogs.findIndex(d => d.id === id);
    const entry = index >= 0 ? dialogs.splice(index,1)[0] : null;
    $('#'+id)?.classList.add('hide'); syncInert();
    const top = dialogs[dialogs.length-1];
    if (entry?.returnTo?.isConnected && (!top || entry.returnTo.closest?.('#'+top.id))) entry.returnTo.focus();
    else if (top) (focusables($('#'+top.id))[0] || $('#'+top.id+' .modal-box'))?.focus();
  }
  function closeAll() { for (const d of [...dialogs].reverse()) closeModal(d.id); }
  document.addEventListener('keydown', event => {
    const top = dialogs[dialogs.length-1]; if (!top) return;
    const mask = $('#'+top.id);
    if (event.key === 'Escape') { event.preventDefault(); (closeHandlers.get(top.id) || (() => closeModal(top.id)))(); return; }
    if (event.key !== 'Tab') return;
    const list = focusables(mask);
    if (!list.length) { event.preventDefault(); mask.querySelector('.modal-box')?.focus(); return; }
    const first = list[0], last = list[list.length-1], active = document.activeElement;
    if (event.shiftKey && (active === first || !mask.contains(active))) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && (active === last || !mask.contains(active))) { event.preventDefault(); first.focus(); }
  });
  document.addEventListener('focusin', event => {
    const top = dialogs[dialogs.length-1]; if (!top) return;
    const mask = $('#'+top.id);
    if (!mask.contains(event.target)) (focusables(mask)[0] || mask.querySelector('.modal-box'))?.focus();
  });
  function localQR(value, container) {
    if (typeof qrcode !== 'function') throw new Error('本地二维码库未加载，请重试或直接复制链接');
    qrcode.stringToBytes = qrcode.stringToBytesFuncs['UTF-8'];
    const code = qrcode(0,'M'); code.addData(String(value),'Byte'); code.make();
    // The SVG contains only generated geometry, never HTML-interpolated subscription data.
    container.innerHTML = code.createSvgTag({cellSize:4,margin:16,scalable:true});
    return code.getModuleCount();
  }
  return {api,download,request,invalidate,invalidateAll,toast,dismissToast,safeText,setError,reportError,runAction,openModal,closeModal,closeAll,localQR,setUnauthorizedHandler:fn=>{unauthorizedHandler=fn;},registerModal:(id,fn)=>closeHandlers.set(id,fn)};
})();
function runAction(button, action) { return UI.runAction(button, action); }
function dismissToast() { UI.dismissToast(); }
