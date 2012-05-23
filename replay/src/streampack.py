'''
Created on 2010-6-10

@author: Yingdi Yu
'''

import struct
import string

def pack(str):
    
    agentpos = string.find(str,' ')
    
    agent = str[0:agentpos]
    
    left = str[agentpos+1:]
    
    commandpos = string.find(left, ' ')
    
    command = left[0:commandpos]
    
    left = left[commandpos+1:]
    
    payload = ""
    
    while True:
        lp = string.find(left, '(')
        type = left[0:lp]
        if type == 'byte':
            rp = string.find(left, ')')
            para = left[lp+1:rp]
            num = string.atoi(para)
            if num > 127:
                num = num-256            
            element = struct.pack('b', num)
            left = left[rp+2:]
        elif type == 'repbyte':
            rp = string.find(left, ')')
            para = left[lp+1:rp]
            rebyte = string.split(para, ',')
            num = string.atoi(rebyte[0])
            if num > 127:
                num = num-256
            format = ""
            count = 0
            while count != string.atoi(rebyte[1]):
                format = format+struct.pack('b',num)
                count += 1
            element = format
            left = left[rp+2:]
        elif type == 'string':
            templeft = left[lp+2:]
            endpos = string.find(templeft, '"')
            element = templeft[0:endpos]
            left = templeft[endpos+3:]
        payload += element
        if len(left) == 0:
            break
    
    return (agent, payload)

def readfile(filename):
    f = file(filename)
    firstline = f.readline()
    info = string.strip(firstline, '[')
    info = string.strip(info, ']')
    withoutport = string.split(info)
    
    infolist = string.split(withoutport[0], '-')
    clientip = infolist[2]
    clientport = string.atoi(infolist[3])
    serverip = infolist[5]
    serverport = string.atoi(infolist[6])
    
    connection_flow = list()
    
    
    while True:
        line = f.readline()
        
        if len(line) == 0: # Zero length indicates EOF
            break
        if(line[0] == '\n' or line[0] == '#'):
            continue
        connection_flow.append(pack(line));
            
    f.close()
    
    return (connection_flow, serverport, clientport)
            
        
    
    
    