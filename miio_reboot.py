#! usr/local/bin/python
# encoding: utf-8
import angr
import claripy
import monkeyhex

import nose
import os
import pickle
#from angrutils import *

import cle
from archinfo import *
import archr
#from archinfo.arch_arm import ArchARM, ArchARMEL, ArchARMHF, ArchARMCortexM

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                         os.path.join('..', '..', 'binaries'))
cus_arch = ArchARMCortexM()


 
def miio_gateway_zigbee(path):
    BASE_ADDR = 0x0
    ENTRYPOINT = 0x0
    thumb = 0x0
    if path.find("gbl") == -1:
        return
#    ENTRYPOINT = 0x10013d
#    blob_file = os.path.join(TEST_BASE, 'tests', 'i386', 'all')
    blob_file = path    #载入文件
    blob_file_size = os.stat(blob_file).st_size
    ld = cle.Loader(blob_file, main_opts={
        'backend': 'blob',
        'base_addr': BASE_ADDR,
        'entry_point': ENTRYPOINT,
        'arch': cus_arch,
    })
    nose.tools.assert_equal(ld.main_object.linked_base, BASE_ADDR)
    nose.tools.assert_equal(ld.main_object.mapped_base, BASE_ADDR)
    nose.tools.assert_equal(ld.main_object.min_addr, BASE_ADDR)
    nose.tools.assert_equal(ld.main_object.max_addr, BASE_ADDR + blob_file_size - 1)
#    nose.tools.assert_equal(ld.main_object.max_addr, 0x480c0043)
    nose.tools.assert_equal(ld.main_object.entry, ENTRYPOINT)
    nose.tools.assert_true(ld.main_object.contains_addr(BASE_ADDR))
    nose.tools.assert_false(ld.main_object.contains_addr(BASE_ADDR - 1))

    # ensure that pickling works
    ld_pickled = pickle.loads(pickle.dumps(ld))
    nose.tools.assert_equal(ld_pickled.main_object.mapped_base, BASE_ADDR)

    p = angr.Project(ld,arch=cus_arch, auto_load_libs=False)
#   p = angr.Project(ld, auto_load_libs=False)
    print(p.arch)

#   修改参考angr-master/tests/test_cfg_thumb_firmware.py
#    cfg = p.analyses.CFGFast(resolve_indirect_jumps=True, force_smart_scan=False, force_complete_scan=False,
#                             normalize=True)

#    print(len(cfg.graph.nodes()))   #打印出节点的个数
#    for addr, func in cfg.graph.nodes.items():
#        print(hex(addr.addr))  #打印出所有nodes的地址
#95d1 5089
    start_state = p.factory.blank_state(addr=0x32f2+1+BASE_ADDR,add_options={"SYMBOLIC_WRITE_ADDRESSES"}) #初始化入口地址
    pass1 = claripy.BVS("pass1",32)  #模拟一个64位的pass1
#    pass2 = claripy.BVS("pass2",32)  #模拟一个64位的pass2
    start_state.regs.r3 = pass1




    sm = p.factory.simulation_manager(start_state)  #模拟运行
#    check_addr9 = 0x21375
#    check_skip_size9 = 2
#    @p.hook(check_addr9, length=check_skip_size9)
#    def hook1(state):
#        state.regs.eax = 1    

#    sm.explore(find=0x21a21+thumb)
#    sm.explore(find=0x225b9+thumb)
#    sm.explore(find=0x3652+1,avoid=0x36b9)
#    sm.explore(find=0x32b2+1,avoid=0x36b9)
    sm.explore(find=0x35da+1,avoid=0x36b9)

    if sm.found: #如果找到
      found_state=sm.found[0]
      password1 = found_state.solver.eval(pass1)  #求解pass1
      f1=open('./angr_crashes_2','w', encoding='UTF-8')

      str1=("0x3263->{}".format(hex(found_state.addr)))
      #print("OUT:{}".format(found_state.posix.dumps(1)))
      #print("IN:{}".format(found_state.posix.dumps(0)))
      str2=("data: {:x}".format(password1)) #{:x}输出16进制数 
      f1.write(str1)
      f1.write(str2)
      f1.close() 
    #else:
     # raise Exception("Solution not found")

