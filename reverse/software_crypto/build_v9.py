"""Offline V9: synthetic adapter E0 + scan-local contact overrides, built from stock."""
from pathlib import Path
import sys, struct, hashlib, json, random
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'emmc_continue'))
sys.path.insert(0,str(ROOT/'reverse/eeprom_adapter'))
import build_eeprom_firmware as asm
from decode_t48_firmware import decode
from build_t48_falling_candidate import i_type,jal_zero,encode_update
from build_t48_bga153_compat_candidate import li
from build_t48_adapter_auto_v5 import IDS
import build_t48_crypto_gpio_v7 as v7
BASE=0x5000
ENTRY=0x3ee34
PIN=0x3edc0
HOOKS=(0x2e880,0x2e936)
PINS=(40,41,43)
asm.ENTRY=ENTRY
a=asm.Asm()
a.label('entry')
a.load(5,11,0);a.imm(6,11);a.branch(0,5,6,'tsop')
# Clear output/flags before selection, including unknown selectors.
for off in range(0,32,4):a.save(0,10,off)
for off in (-0x7af,-0x7b0,-0x7b7):a.save(0,3,off,0)
table_load=len(a.w);a.emit(0,0);a.imm(7,len(IDS))
a.label('lookup');a.load(6,28,0);a.branch(0,5,6,'found')
a.addi(28,28,8);a.addi(7,7,-1);a.branch(1,7,0,'lookup')
a.imm(10,0xd0);a.emit(0x8067)
a.label('found');a.load(6,28,4);a.save(6,10,28)
a.imm(7,1);a.imm(5,0xada00007);a.branch(6,6,5,'other')
a.imm(5,0xada0000d);a.branch(7,6,5,'other')
a.save(7,3,-0x7af,0);a.jump('success')
a.label('other');a.imm(5,0xada00001);a.branch(0,6,5,'special')
a.imm(5,0xada00003);a.branch(0,6,5,'special')
a.save(7,3,-0x7b0,0);a.jump('success')
a.label('special');a.save(7,3,-0x7b7,0)
a.label('success');a.imm(10,0);a.emit(0x8067)
a.label('tsop');a.jump(v7.WRAPPER)
TABLE=a.pc
a.w[table_load:table_load+2]=li(28,TABLE)
code=a.finish()
blob=code+b''.join(struct.pack('<II',sel,0xada00000|ident) for sel,ident in IDS.items())
# Only the call result is substituted. No GPIO/pin mode writes in the stub.
ws=[]
def branch_eq(r1,r2,delta):
 v=delta&8191
 return ((v>>12)<<31)|(((v>>5)&63)<<25)|(r2<<20)|(r1<<15)|(((v>>1)&15)<<8)|(((v>>11)&1)<<7)|0x63
for pin in PINS:
 ws.append(i_type(pin,0,0,5));ws.append(0)
ws.append(jal_zero(0x2f3d4-(PIN+len(ws)*4)))
success=PIN+len(ws)*4
ws.extend([i_type(1,0,0,10),0x8067])
for i in range(len(PINS)):ws[i*2+1]=branch_eq(10,5,success-(PIN+(i*2+1)*4))
pin_blob=struct.pack('<'+'I'*len(ws),*ws)
assert PIN+len(pin_blob)<=v7.WRAPPER and ENTRY+len(blob)<=0x3fe00

def verify(image):
 """Execute actual emitted RV32 words; original GPIO read modeled at its call boundary."""
 count=0
 def run(selector,contact=None,physical=0,seed=0,hook=HOOKS[0]):
  nonlocal count
  rng=random.Random(seed)
  r=[rng.getrandbits(32) for _ in range(32)]
  r[0]=0;r[1]=0x100000;r[2]=0x20008000;r[3]=0x20000898
  r[10]=0x20004000 if contact is None else contact;r[11]=0x20004100
  before=r[:]
  mem={0x20004100+i:v for i,v in enumerate(struct.pack('<I',selector))}
  mem.update({0x20004000+i:0xa5 for i in range(32)})
  for off in (-0x7af,-0x7b0,-0x7b7):mem[r[3]+off]=1
  writes=[];reads=0;pc=0x2aba2 if contact is None else hook
  def get(addr,n):
   if BASE<=addr and addr+n<=BASE+len(image):return int.from_bytes(image[addr-BASE:addr-BASE+n],'little')
   return sum(mem[addr+i]<<(i*8) for i in range(n))
  def signed(v,b):return v-(1<<b) if v&(1<<(b-1)) else v
  for _ in range(1024):
   if (contact is None and pc in (0x100000,v7.WRAPPER)) or (contact is not None and pc==hook+4):break
   if pc==0x2f3d4:
    assert contact is not None and r[10]==contact
    reads+=1;r[10]=physical;pc=r[1];continue
   assert pc in (0x2aba2,*HOOKS) or ENTRY<=pc<TABLE or PIN<=pc<PIN+len(pin_blob),hex(pc)
   w=get(pc,4);op=w&127;d=(w>>7)&31;f=(w>>12)&7;s=(w>>15)&31;t=(w>>20)&31
   imm=signed(w>>20,12);nxt=pc+4
   if op==0x13:
    assert f==0;r[d]=(r[s]+imm)&0xffffffff
   elif op==0x37:r[d]=w&0xfffff000
   elif op==3:
    assert f==2;r[d]=get((r[s]+imm)&0xffffffff,4)
   elif op==0x23:
    assert f in (0,2)
    addr=(r[s]+signed(((w>>25)<<5)|((w>>7)&31),12))&0xffffffff
    for i in range(1 if f==0 else 4):
     assert 0x20004000<=addr+i<0x20004020 or addr+i in (0x200000e9,0x200000e8,0x200000e1)
     mem[addr+i]=(r[t]>>(8*i))&255;writes.append(addr+i)
   elif op==0x63:
    delta=signed(((w>>31)<<12)|(((w>>7)&1)<<11)|(((w>>25)&63)<<5)|(((w>>8)&15)<<1),13)
    assert f in (0,1,6,7)
    if {0:r[s]==r[t],1:r[s]!=r[t],6:r[s]<r[t],7:r[s]>=r[t]}[f]:nxt=pc+delta
   elif op==0x6f:
    delta=signed(((w>>31)<<20)|(((w>>12)&255)<<12)|(((w>>20)&1)<<11)|(((w>>21)&1023)<<1),21)
    if d:r[d]=nxt
    nxt=pc+delta
   elif w==0x8067:nxt=r[1]
   else:raise AssertionError(hex(w))
   r[0]=0;pc=nxt
  else:raise AssertionError('No return')
  for reg in (1,2,3,4,8,9,11,12,13,14,15,16,17,*range(18,28),29,30,31):
   # Hook has ra=hook+4 because it is a call; caller receives that continuation.
   if contact is not None and reg==1:continue
   assert r[reg]==before[reg],reg
  if contact is not None:
   assert pc==hook+4
  if contact is None and selector==11:
   assert pc==v7.WRAPPER and not writes and r[10]==before[10]
  elif contact is None:
   ident=(0xada00000|IDS[selector]) if selector in IDS else 0
   expected=bytes(28)+struct.pack('<I',ident)
   assert bytes(mem[0x20004000+i] for i in range(32))==expected
   assert r[10]==(0 if ident else 0xd0)
   flags=[mem[r[3]+off] for off in (-0x7af,-0x7b0,-0x7b7)]
   ef=[0,0,0]
   if ident:ef[0 if 0xada00007<=ident<0xada0000d else 2 if ident in (0xada00001,0xada00003) else 1]=1
   assert flags==ef
  else:
   assert r[10]==(1 if contact in PINS else physical) and not writes
   assert reads==(0 if contact in PINS else 1)
  count+=1
 # Treat the scan call continuation as the return boundary.
 # A scan hook uses JAL ra, so stop there before decoding original compressed code.
 original_run=run
 for selector in list(IDS)+[11,0,4,0xffffffff,0xed000000]+[random.Random(i).getrandbits(32) for i in range(64)]:
  for seed in range(8):run(selector,seed=seed)
 for hook in HOOKS:
  for contact in range(56):
   for physical in (0,1):run(0,contact,physical,hook=hook)
 return count+v7.verify_wrapper(image)

def main():
 source=(ROOT/'OR/UpdateT48.dat').read_bytes()
 assert hashlib.sha256(source).hexdigest()=='8e18ea5d769bb7375620a84f8c2a8269cd7ef485550cee0325819832e45ff437'
 key=(ROOT/'emmc_continue/t48_key.dat').read_bytes()
 stock,_=decode(source,key);p=bytearray(stock)
 allowed=[]
 def patch(addr,data,empty=False):
  offset=addr-BASE
  if empty:assert stock[offset:offset+len(data)]==b'\xff'*len(data)
  p[offset:offset+len(data)]=data;allowed.append((addr,addr+len(data)))
 patch(ENTRY,blob,True);patch(PIN,pin_blob,True);patch(v7.WRAPPER,v7.wrapper,True)
 assert stock[0x2aba2-BASE:0x2aba6-BASE]==struct.pack('<I',jal_zero(0x2bbda-0x2aba2))
 patch(0x2aba2,struct.pack('<I',jal_zero(ENTRY-0x2aba2)))
 assert stock[0x2abb4-BASE:0x2abb8-BASE]==struct.pack('<I',jal_zero(0x2a364-0x2abb4)|128)
 patch(0x2abb4,struct.pack('<I',0x13))
 for hook in HOOKS:
  assert stock[hook-BASE:hook-BASE+4]==struct.pack('<I',jal_zero(0x2f3d4-hook)|128)
  patch(hook,struct.pack('<I',jal_zero(PIN-hook)|128))
 assert len(p)==len(stock)
 assert all(x==y or any(lo<=BASE+i<hi for lo,hi in allowed) for i,(x,y) in enumerate(zip(stock,p)))
 # Entire driver/configuration/cleanup and normal eMMC admission remain original.
 for lo,hi in [(0x2f2e2,0x2f500),(0x10590,0x106a0),(0x1ee78,0x1eea0),(0x2bbda,0x2bd1e),(0x2a364,0x2a472)]:
  assert p[lo-BASE:hi-BASE]==stock[lo-BASE:hi-BASE]
 checks=verify(p)
 update=encode_update(source,key,p);back,meta=decode(update,key)
 assert back==p and meta['all_block_crcs_valid']
 out=Path(__file__).resolve().parent/'output';out.mkdir(exist_ok=True)
 name='UpdateT48_SOFTWARE_CRYPTO_PINDETECT_V9_UNTESTED.dat'
 (out/name).write_bytes(update);(out/'t48_v9.bin').write_bytes(p)
 report=dict(status='OFFLINE_PASS_NOT_INSTALLED',checks=checks,sha256=hashlib.sha256(update).hexdigest(),
  file=name,base='stock OR/UpdateT48.dat',ids={hex(k):hex(0xada00000|v) for k,v in IDS.items()},
  pin_indices=PINS,pin_hooks=[hex(x) for x in HOOKS],allowed_changes=[[hex(x),hex(y)] for x,y in allowed],
  tsop56='Original E0, deferred mode0 setup, real crypto required',
  emulation='E0 identity/status/flags only; no ATSHA command-level emulation; no EEPROM needed',
  gpio='Scan-local return override only; no persistent state or GPIO writes in stub; stock cleanup/drivers retained',
  limitations=['Not hardware tested','Pin indices are internal, not verified connector numbers',
   'Pin overrides apply to both scanned paths independent of family',
   'Physical faults/loading cannot be repaired by firmware','Direct crypto USB commands remain stock',
   'Only known 15 selectors plus real TSOP56 path supported'],container=meta)
 (out/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(report,indent=2))
if __name__=='__main__':main()
