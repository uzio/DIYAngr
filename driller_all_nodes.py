#! usr/local/bin/python
# encoding: utf-8
import angr
import claripy
import monkeyhex
import logging
import nose
import os
import pickle
from angrutils import *

import cle
from archinfo import *
import archr

from multiprocessing.context import Process

log = logging.getLogger()
# log.setLevel("DEBUG")
#log.setLevel("INFO")
log.setLevel("WARNING")
#log.setLevel("ERROR")
# log.setLevel("CRITICAL")
from fuzz_main import *

#class NParallel(Process):
 #   def __init__(self,project,entry):
  #   super().__init__()

def get_nodes(entry_addr,file_path,main_name):
    File_address = './crashes/%s/endings.txt'%main_name
    f = open(File_address,'a+')
    fout = ''
    start_result = []
    end_result = []
    blob_file = file_path   
    blob_file_size = os.stat(blob_file).st_size
    ld = cle.Loader(blob_file, main_opts={
        'backend': 'blob',
        'base_addr': 0x0,
        'entry_point': entry_addr,
        'arch': ArchARMCortexM(),#bin指定架构
    })   

    p = angr.Project(ld, auto_load_libs=False)
    if file_path.find('.axf') != -1 or file_path.find('.elf') != -1: #如果是axf，则使用自带架构
       p = angr.Project(file_path, auto_load_libs=False)
       p.entry = entry_addr
    cfg = p.analyses.CFGFast(resolve_indirect_jumps=True, force_smart_scan=False, force_complete_scan=False,
                             normalize=True)
    init_state=p.factory.entry_state()

    entry_node = cfg.get_any_node(p.entry)
    print(hex(p.entry))
    entry_func = cfg.kb.functions[p.entry]
    #entry_func = cfg.kb.functions[0xbb9]
    # node_count = 0 #>> 结点计数
    
    #all_nodes = entry_func.block_addrs   #>> Date 8.16 从可迭代序列直接返回列表
    all_nodes = list(entry_func.block_addrs)
    # for addr in all_nodes :   #获得入口下所有结点 #>> Date 8.16 取消结点计数
    #   print(hex(addr))
    #  node_count+=1 #>> #
    #print(node_count)   #结点个数
    #avoid=[13333,0x3f5b] #可添加跳过报错地址
    
    
    #!PATCH!# BL跳转无限制搜索
    # import time
    do = True
    nodes_loop = all_nodes[:]
    
    while do:
      do = False
      appends = []
      for entry in nodes_loop:
        bb = p.factory.block(entry)
        for i in bb.capstone.insns:
          if str(i).find('bl') != -1:
            if i.mnemonic =='blo' or i.mnemonic =='blx':  #XXX 暂时排除一些类型的跳转操作
              continue
            try:
              append = int((i.op_str).strip('#'),16)
            except ValueError :
              logging.error(f"[!] Opps, op is not an immediate number.\naddr: 0x{i.address:X}, mnem:{i.mnemonic}, op:{i.op_str} ")
              bb.capstone.pp()
              raise
            # logging.warning(f" addr: {i.address}, mnem:{i.mnemonic}, op:{append:X}")
            appends.append(append)
            # bb.capstone.pp()
      if  appends:
        issub = lambda x,y: x.issubset(y) #! 子集判断
        if not issub(set(appends), set(all_nodes)):
          all_nodes = list(set(all_nodes) | set(appends)) #! 总结点集合取并集
          # logging.warning(f"all_nodes:{all_nodes}\nloop:{nodes_loop}")
          nodes_loop = list(set(appends)-((set(nodes_loop) & set(appends)))) #!  循环集取(增集- 增集与循环集的交集)
          # logging.warning(f"loop:{nodes_loop}")
          do = True
          # time.sleep(1)
    # exit(0)
    #!PATCH!#      
          
    for entry in all_nodes: # 并行?
     #if entry not in avoid:
      logging.warning("entry:%s"%hex(entry))    
      successors_node_count = 0
      drillering_state = p.factory.blank_state(addr=entry)  #将所有的结点作为入口
      step = drillering_state.step().successors   #判断结点是否还有子结点
      for addr in step :
          # logging.warning("Found node:%s"%hex(addr.addr))
          try:
            logging.warning("Found node:%s"%hex(addr.addr)) #BUG 23-08-05 —— 当HAL_开头的中断函数被添加到检索列表时，出现了angr.errors.SimValueError: Concretized 2 values (must be exactly 1) in eval_exact
          except:
            continue 
          if addr.addr in all_nodes :
             logging.warning("Skipping This Node!")
             successors_node_count = 1 ;   #如果有子结点，并且子结点在cfg图中
      if successors_node_count == 0 :  
         logging.critical("End Node Found!")
         end_result.append(entry)  #如果没有子结点，或者子结点不在cfg图中，将其加入到终点结点
         #bb = p.factory.block(entry)
         #end_result.append(bb.capstone.insns[-1].address)#将结束节点最后一句也加入
    # print("\n",file=f)
    # print("end:",file=f) 
    fout += "\nend\n" #XXX #>>整合结点组合记录文件ending.txt的写操作，减少写入磁盘的频率
    for i in end_result:
      # print(hex(i),file=f)
      fout += f"{hex(i)}\n"
      logging.critical("end_node:%s"%hex(i))  #打印所有终点结点
    data= read_mysql()
    for addr in all_nodes:          #得到一定限制条件下的输入结点
        #if addr not in end_result:
           bb = p.factory.block(addr)
           for i in bb.capstone.insns:
              for iid in range(len(data)):
                 if str(i).find(data[iid][1]) != -1:
                       start_result.append(addr)
                       break
    # print("start:",file=f)
    fout += "start:\n"
    timeout = 5
    import mmap
    with open('temp','wb') as ftemp:
      ftemp.write(b'0'*20)
    with mmap.mmap(os.open('temp',os.O_RDWR),0) as mm:
      for i in start_result:# 以每个函数的起始地址为基准，遍历求解地址大于基准的路径
        # print(hex(i),file=f)
        fout += f"{hex(i)}\n"
        logging.critical("start_result:%s"%hex(i))  #打印所有开始结点
        #cnt = 500
        #while(cnt>=0):
          #mm.seek(0)
          #if (pos := mm.find(b'0')) != -1:#BUG Sometimes pos got -1 but mm still has '0' in string
            #mm.seek(pos)
            #mm.write(b'1')
            #mm.flush()
            #break
          #else:
            #cnt -= 1
          #if cnt == 0: #FIXME An unknown data-race that requires this HACK way to avoid endless loop
            #mm.seek(0)
            #mm.write(b'0'*20) #
        fuzz_node(entry_addr,i,p,end_result,cfg,main_name,timeout=timeout,pos=None)  #对所有结点规划路径，开始约束求解
      mm.close()
      ftemp.close()
    print(fout, file=f)
    #import threading # 尝试多线程监视和控制进程任务
    #_exit = threading.Event()
    #_st_res = start_result[:]
    #timeout = 1
    #while not _exit.is_set():
     #if not _st_res:
      #break
     #i = _st_res.pop()
     #print(hex(i),file=f)
     #logging.critical("start_result:%s"%hex(i))  #打印所有开始结点
     #fuzz_node(entry_addr,i,p,end_result,cfg,main_name,timeout)  #对所有结点规划路径，开始约束求解
     #_exit.wait(1)

    
