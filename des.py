from pyDes import *


file  = input("Enter fileame: ")
f = open(file,encoding="utf8")
data = f.read()
k = des("DESCRYPT", CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
d = k.encrypt(data)
f.close()
outfile = open(r'C:\Users\Ritik\Desktop\test.des.en1','wb')
outfile.write(d)


'''print ("Decrypted: %r" % k.decrypt(d))'''
res = input("Do you want to decrypt this file?")
if res =='yes':



