"""Install an explicitly supplied T48 candidate with a staged stock Xgpro. Run only with user authorization."""
import ctypes as C
from ctypes import wintypes as W
import hashlib,json,subprocess,sys,time,shutil,os
from pathlib import Path
root=Path(os.environ['T48_TOOL_RUNROOT'])
candidate=Path(sys.argv[1])
if not candidate.is_absolute():candidate=root/candidate
candidate=candidate.resolve();expected=sys.argv[2]
check_startup='--check-startup' in sys.argv[3:]
assert hashlib.sha256(candidate.read_bytes()).hexdigest()==expected
assert not subprocess.run(['powershell','-NoProfile','-Command','Get-Process Xgpro -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id'],capture_output=True,text=True).stdout.strip(),'Xgpro already active'
# Xgpro 13.16 fails to find translations when its executable path is long.
stage=root/('run_'+time.strftime('%H%M%S'));stage.mkdir()
print('XGPRO_WORKDIR',stage,flush=True)
for f in (root/'OR').iterdir():
 if f.is_file() and (f.suffix.lower() in {'.ini','.dll','.lst','.dat'} or f.name.lower()=='xgpro.exe'):shutil.copy2(f,stage/f.name)
shutil.copy2(candidate,stage/'UpdateT48.dat')
proc=subprocess.Popen([str(stage/'Xgpro.exe')],cwd=stage)
flash_in_progress=False
try:
 u=C.WinDLL('user32');k=C.WinDLL('kernel32');ps=C.WinDLL('psapi')
 u.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)];u.GetWindowTextW.argtypes=[W.HWND,W.LPWSTR,C.c_int];u.IsWindowVisible.argtypes=[W.HWND];u.GetDlgCtrlID.argtypes=[W.HWND];u.IsWindowEnabled.argtypes=[W.HWND];u.PostMessageW.argtypes=[W.HWND,W.UINT,W.WPARAM,W.LPARAM]
 k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE;k.CloseHandle.argtypes=[W.HANDLE]
 k.ReadProcessMemory.argtypes=[W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)];k.WriteProcessMemory.argtypes=k.ReadProcessMemory.argtypes
 k.VirtualProtectEx.argtypes=[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,C.POINTER(W.DWORD)];k.FlushInstructionCache.argtypes=[W.HANDLE,C.c_void_p,C.c_size_t]
 ps.EnumProcessModulesEx.argtypes=[W.HANDLE,C.POINTER(W.HMODULE),W.DWORD,C.POINTER(W.DWORD),W.DWORD]
 CB=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
 def title(h):
  b=C.create_unicode_buffer(2048);u.GetWindowTextW(h,b,len(b));return b.value
 def snapshot():
  rows=[]
  @CB
  def top(h,l):
   pid=W.DWORD();u.GetWindowThreadProcessId(h,C.byref(pid))
   if pid.value==proc.pid and u.IsWindowVisible(h):
    controls=[]
    @CB
    def child(c,l):
     if u.IsWindowVisible(c):controls.append({'hwnd':c,'id':u.GetDlgCtrlID(c),'text':title(c),'enabled':bool(u.IsWindowEnabled(c))})
     return True
    u.EnumChildWindows(h,child,0);rows.append({'hwnd':h,'title':title(h),'controls':controls})
   return True
  u.EnumWindows(top,0);return rows
 main=None
 for _ in range(50):
  main=next((w['hwnd'] for w in snapshot() if w['title']=='Xgpro v13.16'),None)
  if main:break
  time.sleep(.1)
 if not main:
  print(json.dumps(snapshot(),ensure_ascii=True),flush=True)
  raise RuntimeError('Xgpro startup failed; inspect startup dialogs in the printed snapshot')
 if check_startup:
  time.sleep(2)
  rows=snapshot()
  assert len(rows)==1 and rows[0]['hwnd']==main, 'Unexpected startup dialog: '+json.dumps(rows)
  assert not any('File Lost' in c['text'] for w in rows for c in w['controls']), 'Missing runtime files'
  assert u.PostMessageW(main,0x10,0,0)
  proc.wait(timeout=10)
  print('STARTUP_SUCCESS; no firmware changes; workdir='+str(stage))
  raise SystemExit(0)
 h=k.OpenProcess(0x438,False,proc.pid);assert h
 try:
  mods=(W.HMODULE*256)();n=W.DWORD();assert ps.EnumProcessModulesEx(h,mods,C.sizeof(mods),C.byref(n),3);base=mods[0]
  def read(addr,n):
   b=C.create_string_buffer(n);got=C.c_size_t();assert k.ReadProcessMemory(h,addr,b,n,C.byref(got)) and got.value==n;return b.raw
  def ready_t48(state):
   return len(state)==4 and state[0]==1 and state[1]==1 and state[2]<=99 and state[3]==7
  state=bytes(4)
  for _ in range(30):
   state=read(base+0x401098,4)
   if ready_t48(state):break
   time.sleep(.1)
  startup={'device_state_hex':state.hex(),'candidate':str(candidate),'windows':snapshot()}
  startup_path=root/'reverse'/('startup_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
  startup_path.write_text(json.dumps(startup,indent=2)+'\n',encoding='utf-8')
  print('DEVICE_STATE',state.hex(),'LOG',startup_path,flush=True)
  assert ready_t48(state),'T48 not ready or unsupported device/version; state='+state.hex()+'; inspect '+str(startup_path)
  patches=[(0x8b089,b'\x7d\x0f',b'\x7f\x0f'),(0x28ea,b'\x75\x69',b'\xeb\x69')]
  for off,before,after in patches:assert read(base+off,2)==before
  for off,before,after in patches:
   addr=base+off;old=W.DWORD();assert k.VirtualProtectEx(h,addr,2,0x40,C.byref(old))
   try:
    n=C.c_size_t();buf=C.create_string_buffer(after);assert k.WriteProcessMemory(h,addr,buf,2,C.byref(n)) and n.value==2
   finally:
    tmp=W.DWORD();assert k.VirtualProtectEx(h,addr,2,old.value,C.byref(tmp))
   assert k.FlushInstructionCache(h,addr,2);assert read(addr,2)==after
 finally:k.CloseHandle(h)
 u.PostMessageW(main,0x111,32771,0);time.sleep(.5)
 dialog=None
 for _ in range(50):
  dialog=next((w for w in snapshot() if w['title']=='Reflash Firmware'),None)
  if dialog:break
  time.sleep(.1)
 assert dialog is not None,'Reflash dialog did not appear: '+json.dumps(snapshot())
 assert any(c['id']==1110 and c['text'].strip().startswith('V') for c in dialog['controls']), 'Missing firmware version label: '+json.dumps(dialog)
 assert any(c['id']==1 and c['enabled'] for c in dialog['controls'])
 assert hashlib.sha256((stage/'UpdateT48.dat').read_bytes()).hexdigest()==expected
 logpath=root/'reverse'/('t48_install_'+time.strftime('%Y%m%d_%H%M%S')+'.jsonl')
 with logpath.open('x',encoding='utf-8',buffering=1) as log:
  log.write(json.dumps({'candidate':str(candidate),'sha256':expected,'installer_pid':proc.pid})+'\n')
  flash_in_progress=True
  assert u.PostMessageW(dialog['hwnd'],0x111,1,0)
  success=False
  for _ in range(120):
   time.sleep(1);rows=snapshot();log.write(json.dumps(rows)+'\n')
   texts=[c['text'] for w in rows for c in w['controls']]
   if 'Reflash firmware successful!' in texts:success=True;flash_in_progress=False;break
   if any('failed' in t.lower() for t in texts):flash_in_progress=False;break
  assert success,'Reflash not confirmed; inspect '+str(logpath)
 u.PostMessageW(dialog['hwnd'],0x111,2,0);time.sleep(.4);u.PostMessageW(main,0x10,0,0)
 proc.wait(timeout=10)
 print('FLASH_SUCCESS',expected,'LOG',logpath)
finally:
 # Close only this worker's Xgpro, never interrupt an unconfirmed active flash.
 if proc.poll() is None and not flash_in_progress:
  try:
   for window in snapshot():
    u.PostMessageW(window['hwnd'],0x10,0,0)
   proc.wait(timeout=12)
  except Exception as cleanup_error:
   print('XGPRO_CLOSE_UNCONFIRMED',str(cleanup_error),flush=True)
 elif proc.poll() is None:
  print('FLASH_STATE_UNKNOWN: Xgpro left open; inspect its update dialog. Do not disconnect T48.',flush=True)
