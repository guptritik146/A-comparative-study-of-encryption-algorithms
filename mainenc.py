from __future__ import print_function

from typing import List

#import docx
import PyPDF2
import math
import aes
from pyDes import *
from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join
import time
from operator import xor
from os import urandom
import blowfish
from Crypto.Cipher import Blowfish
from Crypto import Random
import random
import bffinal

if __name__ == '__main__':
    aesenc = 0
    aesdec = 0
    desenc = 0
    desdec = 0
    bfenc = 0
    bfdec = 0
    rsaenc = 0
    rsadec = 0



    def open_file (filename):
        print ("in ", filename)
        if filename[-3:] == "txt":
            return filename
        elif filename[-4:] == "docx":
            doc = docx.Document(filename)
            size = len(doc.paragraphs)
            for i in range(size):
                print(doc.paragraphs[i].text)
        elif filename[-3:] == "pdf":
            file = open(filename, 'rb')
            fileReader = PyPDF2.PdfFileReader(file)
            with open(filename + ".txt", "w") as f:
                for i in range(fileReader.numPages):
                    f.write(fileReader.getPage(i).extractText()+'\n')
            return filename + ".txt"


    going = True
  #  C:/Users/Ritik/Desktop/NS2 Assignment No-6.pdf

    while going:
        choice = input("What do you want to do?\n 1. Encryption and Decryption\n 2. Comparison\n 3. Exit\n")
        if choice == '1':
            print("Select encryption algorithm")
            encc = input(" 1. AES\n 2. DES\n 3. Blowfish\n 4. RSA\n")
            if encc =='1':
                print("What do you want to do?")
                aec = input(" 1. Encrypt a file\n 2. Decrypt a file\n")
                if aec =="1":

                    aes.clear()
                    start = time.time()
                    aes.enc.encrypt_file(open_file(str(input("Enter name of file to encrypt: "))))
                    end = time.time()
                    ta= end-start
                    aesenc = print("Time taken: " + str(end - start))
                    f = open(b"C:\Users\Ritik\Desktop\limes.txt","w")
                    f.write("AES enc:"+str(ta))
                if aec == '2':
                    aes.clear()
                    start = time.time()
                    aes.enc.decrypt_file(open_file(str(input("Enter name of file to decrypt: "))))
                    end = time.time()
                    tad = end-start
                    '''aesdec = print("Time  taken: " + str(end - start))'''
                    f.write("AES dec:" + str(tad))

            if encc =='2':
                    print("DES encryption")
                    file = open_file(input("Enter fileame: "))
                    f = open(file, encoding="utf8")
                    data = f.read()
                    f.close()
                    k = des("DESCRYPT", CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
                    start = time.time()
                    d = k.encrypt(data)
                    end = time.time()
                    f = open(b"C:\Users\Ritik\Desktop\limes.txt", "w")
                    de=end-start
                    desenc = print("Time taken: " + str(end - start))
                    f.write("DES enc:" + str(de))
                    outfile = open(r'C:\Users\Ritik\Desktop\test.des.en1', 'wb')
                    outfile.write(d)
                    y = input("Would you like to decrypt this file?")
                    if y=='yes':
                        start = time.time()
                        data2 = k.decrypt(d)
                        end = time.time()
                        dd = end-start
                        f.write("DES dec:" + str(dd))
                        desdec = print("Time taken: " + str(end - start))
                        doutfile = open(r'C:\Users\Ritik\Desktop\test1.txt', 'wb')
                        doutfile.write(data2)
            if encc =='3':
                print("Blowfish encryption")
                file = open_file(input("Enter fileame: "))
                f = open(file, "rb")
                data = f.read()
                start = time.time()
                data_encrypted = b"".join(bffinal.cipher.encrypt_ctr(data, bffinal.enc_counter))
                end = time.time()
                f = open(b"C:\Users\Ritik\Desktop\limes.txt", "w")
                ben=end - start
                f.write("DES dec:" + str(ben))
                bfenc = print("Time taken: " + str(end - start))

                outfile = open(r'C:\Users\Ritik\Desktop\test.bf.en1', 'wb')
                outfile.write(data_encrypted)
                res = input("Do you want to decrypt this file?")
                if res == 'yes':
                    start = time.time()
                    data_decrypted = b"".join(bffinal.cipher.decrypt_ctr(data_encrypted, bffinal.dec_counter))
                    end = time.time()
                    bd = end - start
                    f.write("DES dec:" + str(bd))
                    bfdec = print("Time taken: " + str(end - start))
                    doutfile = open(r'C:\Users\Ritik\Desktop\test2.txt', 'wb')
                    doutfile.write(data_decrypted)
            if encc == '4':
                print("rsa encryption")
                keys = []  # list to store text from key_generator.txt
                with open(b"C:\Users\Ritik\Desktop\key_generator.txt", 'r') as file:
                    for line in file:
                        for a in line.split():  # split text by space
                            # print(a)
                            keys.append(a)  # add text to keys list
                n = int(keys[2])  # declare n
                e = int(keys[4])  # declare e
                # print(n)
                # print(e)
                start = time.time()
                def encryption(m, e, n):
                    x = pow(m, e, n)
                    return x
                end = time.time()
                f = open(b"C:\Users\Ritik\Desktop\limes.txt", "w")
                re = end - start
                f.write("DES dec:" + str(re))
                rsaenc = print("Time taken: " + str(end - start))
                encrypted_mess = open(b"C:\Users\Ritik\Desktop\encryptedText.txt", 'w')  # create encryptedText.txt
                file = open_file(input("Enter filename: "))
                with open(file) as newFile:
                    for word in newFile:
                        for char in word:
                            print(encryption(ord(char), e, n), file=encrypted_mess)  # encrypt by char and write to file
                print(n, file=encrypted_mess)  # print n and e
                print(keys[4], file=encrypted_mess)
                print("Successfully encrypted")
        elif choice == '2':
            print("Choose your options:\n")
            ch = input("1. Benchmarking Results\n 2. Avalanche\n")
            if ch=='1':
                       print("AES encrypt:"+str(aesenc))
                       print("AES decrypt:" + str(aesdec))
                       print("DES encrypt:" + str(desenc))
                       print("DES decrypt:" + str(desdec))
                       print("Blowfish encrypt:" + str(bfenc))
                       print("Blowfish decrypt:" + str(bfdec))
                       print("RSA encrypt:" + str(rsaenc))
                       '''print("RSA encrypt:" + aesenc)'''
            if ch=='2':
                file = input("Enter plaintext: ")
                def bitstring_to_bytes(x):
                    s = ''.join(str(e) for e in x)
                    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')


                def differentBits(x, y):
                    # convert Bytes to bits, Add zeros for len()=64 and split them
                    x = (bin(int.from_bytes(x, byteorder="big"))[2:])
                    y = (bin(int.from_bytes(y, byteorder="big"))[2:])
                    x = list((64 - len(x)) * str(0) + x)
                    y = list((64 - len(y)) * str(0) + y)
                    counter = 0
                    for i in range(0, 64):
                        if (x[i] != y[i]):
                            counter += 1
                    return counter


                def changeBit(y, i):
                    if (y[i] == 1):
                        y[i] = 0
                    else:
                        y[i] = 1



                counterEcb = 0
                counterCbc = 0
                for j in range(35):
                    x = []
                    for i in range(0, 64):
                        x.append(random.randint(0, 1))

                    y = x.copy()
                    randIndex = random.randint(0, 63)
                    changeBit(y, randIndex)

                    xBytes = bitstring_to_bytes(x)
                    yBytes = bitstring_to_bytes(y)
                    print('msg1= %s\nmsg2= %s\n\n' % (xBytes, yBytes))

                    # ...............................ECB MODE.....................................
                    key = b'This is my key for today'
                    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
                    xEnc = cipher.encrypt(xBytes)
                    yEnc = cipher.encrypt(yBytes)

                    # testing for correct encryption

                    # how many different bits we got
                    counterEcb += differentBits(xEnc, yEnc) / 64

                    # ............................................CBC MODE.......................................
                    bs = Blowfish.block_size
                    key = b'This is my key for today'
                    iv = Random.new().read(bs)
                    ciphercbc = Blowfish.new(key, Blowfish.MODE_CBC, iv)
                    xEnc = iv + ciphercbc.encrypt(xBytes)
                    yEnc = iv + ciphercbc.encrypt(yBytes)

                    '''#testing for correct encryption
                    xDec=ciphercbc.decrypt(xEnc)
                    print("checking if encryption in cbc mode works correctly:")
                    print('msg: %s'%xBytes)
                    print('decrypted msg: %s \n\n'%xDec)'''

                    # how many different bits we got
                    counterCbc += differentBits(xEnc, yEnc) / 64

                print("ECB MODE avg of difference in bits: %s" % (counterEcb / 35.0))
                print("CBC MODE avg of difference in bits: %s" % (counterCbc / 35.0))

                xDec = cipher.decrypt(xEnc)
                print("checking if encryption in ecb mode works correctly:")
                print('msg: %s' % xBytes)
                print('decrypted msg: %s \n\n' % xDec)
        elif choice =='3':
            going = False
        else:
            print("Invalid. Try again.")