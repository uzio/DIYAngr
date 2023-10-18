# BL跳转搜索



​	从中断函数入口地址开始创建的控制流程图(CFG)无法自动追踪多级跳转经过的所有函数。

​	为了让分析结果覆盖尽可能多的函数，我们选择在中断函数中进行反汇编，匹配查找所有BL操作数来获取次级函数的地址并加入待分析队列。

​	通过循环遍历的方式，我们可以获取中断函数中可能跳转的二级函数，以及二级函数中可能跳转的次一级函数。该过程理论上只要存在跳转次级函数的行为，就可以无限搜索。

​	为了避免产生环路，在实现中限制了循环中的函数地址不可重复。

```python
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
            appends.append(append)
      if  appends:
        issub = lambda x,y: x.issubset(y) #! 子集判断
        if not issub(set(appends), set(all_nodes)):
          all_nodes = list(set(all_nodes) | set(appends)) #! 总结点集合取并集
          nodes_loop = list(set(appends)-((set(nodes_loop) & set(appends)))) #!  循环集取(增集- 增集与循环集的交集)
          do = True
```



