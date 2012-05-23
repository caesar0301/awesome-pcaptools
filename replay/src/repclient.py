'''
Created on 2010-6-10

@author: Yingdi Yu
'''

import socket  
import streampack
import time
import sys
import struct


def main(args):
    filename = args[3]
    
    connectioninfo = streampack.readfile(filename)
    print 'length', len(connectioninfo[0])
    
#    interval = (0.01, 0.02, 0.04, 0.1, 0.2, 0.4)
    interval =(1, 2, 4, 10, 20, 40)
    for i in range(0,6):
        replay(args, connectioninfo, interval[i])
    ans = raw_input('Continue?(y/n) ')
    
def replay(args, connectioninfo, interval):
    time.sleep(180)
    print 'Rate Level', interval
    
    
    serverport = connectioninfo[1]
    clientport = connectioninfo[2]
#    print clientport
#    print serverport
    connectionflow = connectioninfo[0]
    
    length = len(connectionflow)
    
#    ans = raw_input('Continue?(y/n) ')
    ans = 'y'
    if ans[0] == 'y':
        
        print 'Start'
    
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 2)  
        sock.bind((args[2], clientport))
        sock.connect((args[1], serverport))  
        
        count = 0
        sock.send(connectionflow[count][1])
        count = 1
        
        bcount = 0

        start = time.clock()
        partial = ""
        
        while True:        
            curcon = connectionflow[count]
            curlen = len(curcon[1])
            if curcon[0] == 'client':
                sock.send(curcon[1])
                count += 1
            elif curcon[0] == 'server':    
                # If partial is not empty, last action is not finished
                if partial != "":
                    # If partial does not equal to curcon
                    if cmp(partial, curcon[1]) != 0: 
                        # Acquire the left part
                        
                        leftlength = len(curcon[1]) - len(partial)
                        temp = sock.recv(leftlength)        
                        partial += temp
                        if len(curcon[1]) > len(partial):
                            partiallen = len(partial)
                            if cmp(curcon[1][0:partiallen], partial) == 0:
                                continue
                            else:
                                print 'Berror'
                                print 'ltemp', len(temp)
                                print 'lpart', len(partial)
                                print 'lcurc', len(curcon[1])
                                print 'temp', struct.unpack(str(len(temp))+'B', temp)
                                print 'partia', struct.unpack(str(len(partial))+'B', partial)
                                print 'curcon', struct.unpack(str(len(curcon[1]))+'B', curcon[1])
                                break
                            
                    # If partial equals to curcon
                    partial = ""
                    bcount += curlen
                    count += 1
                # If partial is empty, begin new action 
                else:
                    temp = sock.recv(curlen)
                    if cmp(temp, curcon[1]) != 0:
                        templength = len(temp)
                        if templength < curlen:
                            if cmp(temp,curcon[1][0:templength]) == 0:
                                partial = temp
                            else:
                                print 'Aerror'
                                break
                        else:
                            print 'Cerror'
                            break
                    else:
#                        print count
                        partial = ""
                        bcount += curlen               
                        count += 1
            else:
                print 'Derror'
                
            if count >= length:
                break
        end = time.clock()
#        print count
#        print struct.unpack(str(len(temp))+'B', temp)
#        print struct.unpack(str(len(curcon[1]))+'B', curcon[1])
#        ans = raw_input('Continue?(y/n) ')
        sock.close()
        
        print 'Duration',end-start, 'seconds'
        print 'Rate', (bcount*8/(end-start))
    
if __name__ == "__main__":    
    sys.exit(main(sys.argv))