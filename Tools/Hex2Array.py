
while(True):
    Input=str(raw_input("\r\nPlease input HEX stream\r\n"))
    print(Input)
    if len(Input) % 2 != 0:
        print("The string you input was incorrect")
        continue
    print("0x00,"*8)
    print("0x%x,"%(len(Input)//2)),
    for i in range(0,len(Input)//2):
        if i % 8 == 0:print("");
        print("0x%s%s,"%(Input[i*2],Input[i*2+1])),
