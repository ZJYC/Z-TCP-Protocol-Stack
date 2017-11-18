

while(1):
    res = ""
    print("\r\n***************************Print to Hex***************************\r\n")
    while(True):
        Input = str(raw_input("Input 'OVER' to end...\r\n"))
        if Input == "OVER":break
        Input = Input.replace(" ","")
        Input = Input.replace("\r\n","")
        res += Input

    print("Res is :%s"%res)
    print("Len is :%d"%len(res))
    if(len(res)%2 == 1):
        print("len != 2X,So input again...");continue
    raw_input("Input any key to continue...")

    Len = len(res)
    i = 0
    while(1):
        if i >= Len:break
        if i % 32 == 0:print("\n%04X  "%(i//2)),
        print(res[i]+res[i+1]+" "),
        i += 2
    print("      "),




