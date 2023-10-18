#! usr/local/bin/python
# encoding: utf-8
import serial
import serial.tools.list_ports
import time
import threading
import os


def get_com_list():
    global port_list
    # a = serial.tools.list_ports.comports()
    # print(a)
    # port_list = list(serial.tools.list_ports.comports())
    port_list = serial.tools.list_ports.comports()
    return port_list


def set_com_port(n=0):
    global port_list
    global port_select
    port_select = port_list[n]
    return port_select.device


# 打开串口
def serial_open(ser,n):
    global COMM
    serial_port = set_com_port(n)
    ser.port=serial_port
    ser.baudrate=9600
    ser.bytesize=8
    ser.stopbits=1
    ser.parity="N"#奇偶校验位 N－无校验，E－偶校验，O－奇校验
    ser.open()
    COMM = ser   #波特率设置
    if COMM.isOpen():
        #print(serial_port, "open success")
        return 0
    else:
        print("open failed")
        return 255


# 关闭串口
def serial_close():
    global COMM
    COMM.close()
    #print(COMM.name + "closed.")


def send(ser,send_data):
    if(ser.isOpen()):
#        ser.write(send_data.encode('utf-8'))#编码
        ser.write(send_data)
        #print("发送成功",send_data)
        print("发送成功\n")
    else:
        print("发送失败！")


def uart_main(data,func,main_name):
    ser = serial.Serial()
    COMM = serial.Serial()		# 定义串口对象
    get_com_list()
    len = port_list.__len__()
#    print(port_list)
    device = port_list[0].device
#    print(len, device)
    serial_open(ser,0)
    buf = bytes.fromhex(data)
#    print('buf',buf)
    send(ser,buf)
    ser.flushInput()
    #time.sleep(1)
    time.sleep(0.1)# 延时0.1秒，免得CPU出问题
    count = ser.inWaiting() # 获取串口缓冲区数据
    if count !=0 :
        recv = ser.read(ser.in_waiting).decode("gbk") # 读出串口数据，数据采用gbk编码
        print(" --- recv --> ", recv) # 打印一下子
        File_address = './crashes%s/seeds/%s/{ssid:message->%s}'%(main_name,hex(func),recv)
        f = open(File_address,'w+')
        print('send ',data,file=f)
        print('sleep 0.05',file=f)
        serial_close()
        #break
    #time.sleep(0.1) 
    #serial_close()
    #serial_close()

