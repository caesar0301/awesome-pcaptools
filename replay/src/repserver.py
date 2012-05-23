'''
Created on 2010-6-10

@author: Yingdi Yu
'''

import socket  
import streampack
import time
import sys
import string

def main(args):
    filename = args[2]
    
    connectioninfo = streampack.readfile(filename)
    
#    interval = (0.01, 0.02, 0.04, 0.1, 0.2, 0.4)
    interval = (1, 2, 4, 10, 20, 40)
    for i in range(0,6):
        replay(args, connectioninfo, interval[i])
    ans = raw_input('Continue?(y/n) ')
    
def replay(args, connectioninfo, interval):
    print 'interval', interval
    
#    print 'finish'
    
    serverport = connectioninfo[1]
    clientport = connectioninfo[2]
    connectionflow = connectioninfo[0]
    
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 2)
    sock.bind((args[1], serverport))  
    sock.listen(1)
    
    count = 0
    length = len(connectionflow)
    timecount = 0
    
    connection,address = sock.accept()
#    print address
    
    while True:  
        curcon = connectionflow[count]
        if curcon[0] == 'server':
            if timecount == interval:
                timecount = 0
                time.sleep(0.01)
            timecount += 1
            connection.send(curcon[1])
            count += 1
        elif curcon[0] == 'client':
            temp = connection.recv(len(curcon[1]))
            count += 1
        else:
            print 'error'
            
        if count >= length:
            break
    sock.close()

if __name__ == "__main__":    
    sys.exit(main(sys.argv))           
