#! usr/local/bin/python
# encoding: utf-8
import angr
import claripy
import monkeyhex
import logging
import nose
import os
import sys
import pickle
from angrutils import *
import time
from multiprocessing.context import Process
import cle
from archinfo import *
import archr
import pymysql
import signal
import fcntl
import mmap

log = logging.getLogger()
# log.setLevel("DEBUG")
#log.setLevel("INFO")
#log.setLevel("WARNING")

# log.setLevel("CRITICAL")

class FTimer(Process):
    def __init__(self,entry_addr,fuzz_addr,sm,end_addr,pass0,register_target,locate,main_name,timeout=1,pos=None):
      super().__init__()
      self.entry_addr = entry_addr
      self.fuzz_addr = fuzz_addr
      self.sm = sm
      self.end_addr=end_addr
      self.pass0 = pass0
      self.register_target = register_target
      self.locate = locate
      self.main_name = main_name
      self.timeout = timeout
      if pos is not None:
        self.pos = pos if pos >=0 else 0
      else:
        self.pos = None
      pass
    
    def handler(self, signum, frame):
      print(f"[$]timeout, PID {self.pid} terminated.", file=sys.stderr)
      try:
        if self.pos is not None:
          fd = os.open('temp',os.O_RDWR)
          while not self.getLock(fd):
            time.sleep(0.01)
          with mmap.mmap(fd,0) as mm:
            #print(f"OT!BF>PID:{self.pid},pos:{self.pos},mmap:{mm[:]}")
            mm.seek(self.pos)
            mm.write(b'0')
            mm.flush()
            #print(f"OT!AF>PID:{self.pid},pos:{self.pos},mmap:{mm[:]}")
            mm.close()
            self.unLock(fd)
        os.kill(self.pid, 9)
      except ProcessLookupError:
        pass

    def getLock(self, fp):
      try:
        fcntl.flock(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
      except Exception as e:
        return False
    
    def unLock(self, fp):
      try:
        fcntl.flock(fp, fcntl.LOCK_UN)
        return True
      except Exception as e:
        return False
 
    def run(self):
#        fuzz_node(self.fuzz_addr,self.p,self.end_result)
      signal.signal(signal.SIGALRM, self.handler)
      signal.alarm(self.timeout)
      self.sm.explore(find=self.end_addr)  
      if self.sm.found:
         found_state=self.sm.found[0]
         password0 = found_state.solver.eval(self.pass0)
         #print(password0)
         print(chr(password0),'   ',hex(password0))  #ascii hex
         scope = lambda x: x >= 0 and x <= 0xff  #如果是ascii码，改为0x30->0x7a 不是ascii码，改为0x0->0xff
         if scope(password0):
          #File_address = './test/%s->%s'%(hex(self.fuzz_addr),hex(self.end_addr))
          parent_address = f'./crashes/{self.main_name}/{hex(self.entry_addr)}'
          if not os.path.exists(parent_address):
            os.makedirs(parent_address)
          #File_address = './crashes/%s/%s/ssid:%d'%(self.main_name,hex(self.entry_addr),self.locate)
          File_address = parent_address + f'/ssid:{self.locate}'
          if os.path.exists(File_address) == False:
            f = open(File_address,'w+')
          f = open(File_address,'a+')
          while not self.getLock(f):#
            time.sleep(0.01)#            
          print(self.register_target,' iid:',hex(password0),"    Generated From",hex(self.fuzz_addr)," -> ",hex(self.end_addr),(type(password0)),file=f)#,'ascii:',chr(password0),file=f)
          self.unLock(f)#
          
          if self.pos is not None:
            fd = os.open('temp',os.O_RDWR)
            while not self.getLock(fd):
              time.sleep(0.01)
            with mmap.mmap(fd,0) as mm:
              #print(f"BF>PID:{self.pid},pos:{self.pos},mmap:{mm[:]}")
              mm.seek(self.pos)
              mm.write(b'0')
              mm.flush()
              #print(f"AF>PID:{self.pid},pos:{self.pos},mmap:{mm[:]}")
              mm.close()
              self.unLock(fd)
          #print('locate:',self.locate,file=f)
          #return 1

data = None

def read_mysql():
   conn = pymysql.connect(
       host="localhost",
       user="root",
       passwd="991121",
       db="angr"
   )
   cursor = conn.cursor()
   sql ="SELECT * FROM angr.measure;"
   cursor.execute(sql)
   conn.commit()
   data = cursor.fetchall()
   return data


def fuzz_node(entry_addr,fuzz_addr,p:angr.Project,end_result,cfg,main_name,timeout=1, pos=None):
    log.setLevel("ERROR") #warning
    start_state = p.factory.blank_state(addr=fuzz_addr)
    global data
    if data is None:
     data= read_mysql()
    else:
       pass
    locate16 = '0'
    locate = int(locate16,base=16) 
    register_target ='none'
    fuzz_register ='none'  #初始化防止报错
    entry_node = cfg.get_any_node(fuzz_addr)
    bb = p.factory.block(fuzz_addr)
    flag = 0
    for i in bb.capstone.insns:  #检查是否有基地址初始化，跳过
        if str(i).find('pc') != -1:
           fuzz_addr +=2  
        if str(i).find('strb') != -1:
           fuzz_addr +=2 
    print("[*] Fuzzing From ",hex(fuzz_addr))
    start_state = p.factory.blank_state(addr=fuzz_addr)
    start_state.regs.r0 = 0
    start_state.regs.r1 = 0
    start_state.regs.r2 = 0
    start_state.regs.r3 = 0
    start_state.regs.r4 = 0
    start_state.regs.r5 = 0
    pass0 = start_state.solver.BVS("pass0",8)
  ##
    for i in bb.capstone.insns:
       for iid in range(len(data)):
         if str(i).find(data[iid][1]) != -1:
            if data[iid][1] == "cmp":
               start = str(i).find('r')+data[iid][2]
               register_target =str(i)[start:start+2]
    for i in bb.capstone.insns:
       for iid in range(len(data)):
         if str(i).find(data[iid][1]) != -1:
            if data[iid][1] != "cmp":
              start = str(i).find('r')+data[iid][2]
              register_trans =str(i)[start:start+2]
              if register_trans == register_target:
                if str(i).find('#') != -1:
                  start = str(i).find('#')
                  end = str(i).find(']')
                  locate16 = str(i)[start+1:end].zfill(2)
                  locate = int(locate16,base=16)
                else:
                  locate16 = '0'
                start = str(i).find('[')+1
                fuzz_register = str(i)[start:start+2]
    if fuzz_register == 'r0':
         start_state.memory.store(start_state.regs.r0+locate,pass0)
    if fuzz_register == 'r1':
         start_state.memory.store(start_state.regs.r1+locate,pass0)
    if fuzz_register == 'r2':
         start_state.memory.store(start_state.regs.r2+locate,pass0)
    if fuzz_register == 'r3':
         start_state.memory.store(start_state.regs.r3+locate,pass0)
    if fuzz_register == 'r4':
         start_state.memory.store(start_state.regs.r4+locate,pass0)
    if fuzz_register == 'r5':
         start_state.memory.store(start_state.regs.r5+locate,pass0)
    #print('fuzz',fuzz_register)
    print('locate',locate)
    #time.sleep(2)
    #跳过基地址初始化，全部设为1
    if fuzz_register != 'none':
     sm = p.factory.simulation_manager(start_state)

     for succ_addr in entry_node.successors:   #先遍历子结点
       print("[*] Fuzzing To ",hex(succ_addr.addr))
       works = FTimer(entry_addr,fuzz_addr,sm,succ_addr.addr,pass0,register_target,locate,main_name,timeout,pos=pos)
       works.daemon = True
       works.start()
       #a = works.run
       #time.sleep(1) # 设定函数超时时间，超过1秒将停止函数运行
       #works.terminate()
       #while(works.is_alive()):
        #print('wait...', end='\r')
       #if a == 1:
       #   break
     for end_addr in end_result:     #再遍历所有结束点
      if end_addr > fuzz_addr:
       print("[*] Fuzzing To ",hex(end_addr))
       works = FTimer(entry_addr,fuzz_addr,sm,end_addr,pass0,register_target,locate,main_name,timeout,pos=pos)
       works.daemon = True
       works.start()
       #a = works.run
       #time.sleep(1) # 设定函数超时时间，超过1秒将停止函数运行
       #works.terminate()
       #while(works.is_alive()):
        #print('wait...', end='\r')
      #if a == 1:
      #   break


