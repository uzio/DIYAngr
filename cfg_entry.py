#! usr/local/bin/python
# encoding: utf-8
import angr
import claripy
import monkeyhex

import nose
import os
import pickle
from angrutils import *
import os
import cle
from archinfo import *
import archr
#from forwork import *
#from archinfo.arch_arm import ArchARM, ArchARMEL, ArchARMHF, ArchARMCortexM

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                         os.path.join('..', '..', 'binaries'))
cus_arch = ArchARMCortexM()

def entry_get(file_path_axf,flag,function_info):
    os.makedirs('./%s_cfg'%file_path_axf,exist_ok=True)
    entrys=[]
    p = angr.Project(file_path_axf)
    #print(hex(p.loader.min_addr)) axf -> base_addr
    cfg = p.analyses.CFGFast()
    f = cfg.kb.functions
    for addr, func in f.items():
     for info in function_info:
      if func.name.find("".join(info)) != -1 or hex(addr).find("".join(info)) != -1:
        print("find   ",hex(addr), func.name)
        plot_cfg(cfg, "./%s_cfg/%s"%(file_path_axf,func.name), asminst=True, vexinst=False, func_addr={addr: True},debug_info=False, remove_imports=True, remove_path_terminator=True)  #将所有可能的图打印，手动进行二次选择 
        if flag == 0:
           entrys.append(addr-p.loader.min_addr)
        else:
           entrys.append(addr)
        break

    return entrys

def entry_get_bin(file_path):
    os.makedirs('./%s_cfg'%file_path,exist_ok=True)
    entrys=[]
    blob_file = file_path   
    blob_file_size = os.stat(blob_file).st_size
    ld = cle.Loader(blob_file, main_opts={
        'backend': 'blob',
        'base_addr': 0x0,
        'entry_point': 0,
        'arch': ArchARMCortexM(),
    })
    p = angr.Project(ld, auto_load_libs=False)
    cfg = p.analyses.CFGFast(resolve_indirect_jumps=True, force_smart_scan=False, force_complete_scan=False,
                             normalize=True)
    f = cfg.kb.functions
    for addr, func in f.items():
        print("find   ",hex(addr), func.name)
        plot_cfg(cfg, "./%s_cfg/%s"%(file_path,hex(func.addr)), asminst=True, vexinst=False, func_addr={addr: True},debug_info=False, remove_imports=True, remove_path_terminator=True) 
        entrys.append(addr)
    return entrys
