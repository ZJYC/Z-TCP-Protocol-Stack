# -*- coding: utf-8 -*-
while(True):
    Input=str(raw_input("\r\nPlease input HEX stream\r\n"))
    print(Input)
    if len(Input) % 2 != 0:
        print("The string you input was incorrect")
        continue
    print("0x00,"*4)
    print("0x00,"*1)
    L = len(Input)//2
    L1,L2,L3,L4 = (L>>24)&(0xFF),(L>>16)&(0xFF),(L>>8)&(0xFF),(L>>0)&(0xFF)
    print ("0x%02X,"%(L1)),
    print ("0x%02X,"%(L2)),
    print ("0x%02X,"%(L3)),
    print ("0x%02X,"%(L4)),
    for i in range(0,L):
        if i % 8 == 0:print("");
        print ("0x%s%s,"%(Input[i*2],Input[i*2+1])),
