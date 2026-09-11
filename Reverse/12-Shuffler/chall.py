import random
import hashlib
encrypted=''
data=input('Hello enter the string you want to encrypt: \n')
data+="A"
if len(data)==40:
    if hashlib.md5(data[:39].encode()).hexdigest()=="ac9dc5b77c199d4737f5010da0fcdd24":
        print("You got a hidden gem")
    for i in range(40):
        encrypted+=chr(ord(data[i])^(i<<3))
    simp=[encrypted[i:i+8]for i in range(0,len(data),8)]
    random.shuffle(simp)
    with open('flag.enc','w', encoding="utf-8")as file:
        file.write(''.join(simp))
else:
    print('We Only Encrypt Strings with legnth = 39')
