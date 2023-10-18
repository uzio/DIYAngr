#! usr/local/bin/python
# encoding: utf-8
import os
import sys
from driller_all_nodes import *
from cfg_entry import *
import shutil
import random
import mmap
from python_uart import *
import time
from math import ceil, log2
from multiprocessing.context import Process

class GrowingList(list):
    '''auto-growing list, with random value filled'''
    def __setitem__(self, index, value):
        if index >= len(self):
          glength = 2**ceil(log2(index))-len(self)
          #self.extend([0x00]*glength)
          self.extend([random.randint(0x00,0xff) for _ in range(glength)])
        list.__setitem__(self, index, value)

def read_one(txt_path):
    read_data=[]
    wen_jian = open('%s'%txt_path)
    for linedata in wen_jian.readlines():
        linedata = str(linedata).replace("\n","")
        cut = linedata.find("     G")
        #print(cut)
        linedata = linedata[0:cut]
        #print(linedata)
        if int(linedata.split(":", 1)[1],16) not in read_data: #去除重复数据
          read_data.append(int(linedata.split(":", 1)[1],16))
    return(read_data)
        
def read_function(inputpath):
    with open(inputpath, 'r', encoding='utf-8') as infile:
         data1 = []
         for line in infile:
                data_line = line.strip("\n").split()  # 去除首尾换行符，并按空格划分
                if len(data_line) != 0:
                  data1.append(data_line)
    infile.close()
    return data1




#def demo_solve_uart(path):
def main(path,info_path,is_custom):
    seedsnum=0
    #path = './Drone.elf' #测试用例
    function_info = read_function(info_path)  #调用txt载入目标函数信息
    entrys=[]
    #entrys = [0x8000423]  #不含axf时需要手动写入需要探索的地址  可以手动指定探索哪个函数，节省时间
    seeds=[]
    if path.find('.bin') != -1:  #为bin文件
      file_path_bin= path #载入的文件地址
      file_path_axf = file_path_bin.replace("bin","axf")
      if os.path.exists(file_path_axf) == False:
          print("[*] WARNING! Need Axf for Bin!")
      if entrys == []:   #对于bin文件，如果没有手动指明哪个函数地址，就遍历所有函数
        print("[*] Entrys Is Empty!")
        #entrys = entry_get_bin(file_path_bin,function_info)
        entrys = entry_get_bin(file_path_bin)#bin文件如果没有axf提供包含函数名bootloader
    #elif path.find('.axf') != -1:  #为axf文件
    else :  #elf文件
         entrys = entry_get(path,1,function_info) 
    #print(entrys)


    #full_name = path.split('/')[-1] if path.find('/') != -1 else path
    basename = os.path.basename(path)
    main_name = basename.split('.')[0] if basename.find('.') != -1 else basename
    if os.path.exists('./crashes/%s'%main_name):
      shutil.rmtree('./crashes/%s'%main_name)
    for entry_addr in entrys:
        os.makedirs('./crashes/%s/%s'%(main_name,hex(entry_addr)),exist_ok=True)
        get_nodes(entry_addr,path,main_name)
    for entry_addr in entrys:
      if os.listdir('./crashes/%s/%s'%(main_name,hex(entry_addr))) != []: #delete
         seeds.append(entry_addr)
      else:
         shutil.rmtree('./crashes/%s/%s'%(main_name,hex(entry_addr)))

    #qemu还是手动接线
    qemu_flag = 1 #选择是否是固件还是选用qemu  固件:0 // qemu:1
    
    if qemu_flag == 0:
      seeds=[0xc29]  #注释掉就选择所有中断为入口，固件需更改接线(qemu从seeds中手动挑选) 目前只支持一个一个探索
      print("[*] Start Fuzzing In UART")
    elif qemu_flag == 1:
      print("[*] Start Fuzzing In QEMU")


    #从crashes队列中读取字符串需要变异的位置以及可供选择变异的值
    all_data=dict()
    testbuf = ''
    logging.debug("If Something ERROR,Please Check cfg_entry.py line31")  #如果缺函数，请修改或核对cfg_entry.py line31
    time.sleep(3)
    for func in seeds:
        print("[*] Target Is ",hex(func))
        list_addr = os.listdir('./crashes/%s/%s'%(main_name,hex(func)))
        for i in list_addr:
            all_data[i]=read_one('./crashes/%s/%s/%s'%(main_name,hex(func),i))
        #random_buf= '21'+"".join([random.choice("0123456789abcde")for i in range(60)])+'ff'  #生成64位随机16进制
        os.makedirs('./crashes/%s/seeds/%s'%(main_name,hex(func)),exist_ok=True)
        #print(all_data.items()) #查看items
        #print(len(os.listdir('./crashes/seeds/%s'%hex(func))))
        while len(os.listdir('./crashes/%s/seeds/%s'%(main_name,hex(func)))) <10:  #qemu测试生成至多10个种子 固件只需1个 固件修改为：while *** == 0:
         #if qemu_flag == 0:
         #  random_buf= '21'+"".join([random.choice("0123456789abcde")for i in range(124)])+'ff'
         #if qemu_flag == 1:  #变异范围为ascii码表  
         # random_buf= '21'+"".join([hex(random.randrange(48,57,1)).split('x')[-1]for i in range(31)])
         #random_buf= '21'+"".join([random.choice("0123456789abcde")for i in range(128-4)])+'ff'   #生成64个16进制的数值，如需修改位数，上下需同时修改
         random_buf= "".join([random.choice("0123456789abcde")for i in range(64)])   #生成256个16进制的数值，如需修改位数，上下需同时修改
         #random_buf= "".join(["0" for i in range(128)])
         for i in all_data.items():
           testbuf = ''
           #locate = int(i[0][5:],10) #XXX Update 07-25-23
           locate = (int(i[0][5:],10)+1)*2-1  #u16
           #print(locate)
           data = i[1][random.randint(0,len(i[1])-1)]
           #print(data)
           buf = bytes.fromhex(random_buf)
           #buflist = list(buf) #sometimes crashed by IndexError
           buflist = GrowingList(buf)
           #print(buflist)
           try:
            buflist[locate] = data #变异位置     不再局限于ascii码内
           except IndexError:
            print("[*] 超过种子长度限制.") 
           for i in buflist:
              testbuf += str(hex(i)[2:].zfill(2))
           random_buf =  str(testbuf) #保留单次变异结果
         File_address = './crashes/%s/seeds/%s'%(main_name,hex(func))
         Seeds_address = './crashes/%s/seeds/%s/%d'%(main_name,hex(func),seedsnum)
         if qemu_flag == 0:
            uart_main(testbuf,func,main_name)
            print(testbuf)
         elif qemu_flag == 1:
            f = open(Seeds_address,'w+')
            #teststring = "a"*(64-1)       #生成64个16进制的数值，如需修改位数，上下需同时修改
            teststring = "a"*(len(buflist)-1)       #生成256个16进制的数值，如需修改位数，上下需同时修改
            print(teststring,file=f)
            #以下选择输出ascii类型 qemu   不再局限于ascii码内
            #ascii_string=''.join([chr(int(b, 16)) for b in [testbuf[i:i+2] for i in range(0, len(testbuf), 2)]])
            f.close()
            f = open(Seeds_address,'r+')
            m = mmap.mmap(f.fileno(), 0)
            m[:] = bytes.fromhex(random_buf)
            #os.system('./input.sh '+ascii_string)  #发送qemu
            #time.sleep(0.1)
            #os.system('./enter.sh')
            ##print('echo -n "',ascii_string,'" > /dev/pts/1 ',file=f)
            ##print('echo -e "\r\n" > /dev/pts/1',file=f)
            m.close()
            f.close()
         time.sleep(0.5) #每0.5s发送一次
         seedsnum = seedsnum+1
        print("[*] 0x{:x} Seeds Complited!".format(func))
        if is_custom:
         P2IMpath = input("[*] Enter the Path of P2IM INPUTS:")
        else:
         from datetime import datetime
         now = datetime.now()
         timestr = now.strftime("%d-%m-%Y")
         basename = os.path.basename(path)
         namedir = basename.split('.')[0] if basename.find('.') != -1 else basename
         P2IMpath = '/home/uzio/Projects/P2IM/seeds/'+ namedir + '/' + timestr
         for i in range(200):
          seedpath = P2IMpath + f'/s{i}'
          if os.path.exists(seedpath):
           continue
          else:
           os.makedirs(seedpath)
           P2IMpath = seedpath
           break
         
        cmd='cp -r {}/* {}'.format(File_address,P2IMpath)
        os.system(cmd)
        #for i in all_data:
            #if isinstance(i,str): #判断是否为字符串
            #   print(i) 
        #uart_main(testbuf) #发送变异好的字符串
        #time.sleep(1)
    #将值输入uart中
    print("[*] Works Completed!")

if __name__ == "__main__":
    path = sys.argv[1]
    info_path = sys.argv[2]
    tic = time.perf_counter()
    main(path,info_path,False)
    toc = time.perf_counter()
    e_time = toc - tic
    print(f"Elapsed time: {e_time:0.4f} s")

