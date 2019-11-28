from Crypto.Cipher import Blowfish
from Crypto import Random
import random

file = input("Enter fileame: ")
f = open(file)
x = f.read()
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


# ...................................MAIN...........................................
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
    print('msg1= %s\nmsg2= %s\n\n'%(xBytes,yBytes))


    # ...............................ECB MODE.....................................
    key = b'This is my key for today'
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    xEnc = cipher.encrypt(xBytes)
    yEnc = cipher.encrypt(yBytes)

    #testing for correct encryption


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

xDec=cipher.decrypt(xEnc)
print("checking if encryption in ecb mode works correctly:")
print('msg: %s'%xBytes)
print('decrypted msg: %s \n\n'%xDec




if os.path.isfile('data.txt.enc'):
    while True:
        password = str(input("Enter password: "))
        enc.decrypt_file("data.txt.enc")
        p = ''
        with open("data.txt", "r") as f:
            p = f.readlines()
        if p[0] == password:
            enc.encrypt_file("data.txt")
            break

    while True:
        clear()
        choice = int(input(
            "1. Press '1' to encrypt file.\n2. Press '2' to decrypt file.\n3. Press '3' to Encrypt all files in the directory.\n4. Press '4' to decrypt all files in the directory.\n5. Press '5' to exit.\n"))
        clear()
        if choice == 1:
            enc.encrypt_file(str(input("Enter name of file to encrypt: ")))
        elif choice == 2:
            enc.decrypt_file(str(input("Enter name of file to decrypt: ")))
        elif choice == 3:
            enc.encrypt_all_files()
        elif choice == 4:
            enc.decrypt_all_files()
        elif choice == 5:
            exit()
        else:
            print("Please select a valid option!")

else:
    while True:
        clear()
        password = str(input("Setting up stuff. Enter a password that will be used for decryption: "))
        repassword = str(input("Confirm password: "))
        if password == repassword:
            break
        else:
            print("Passwords Mismatched!")
    f = open("data.txt", "w+")
    f.write(password)
    f.close()
    enc.encrypt_file("data.txt")
    print("Please restart the program to complete the setup")
    time.sleep(15)

    file = input("Enter fileame: ")
    f = open(file, encoding="utf8")
    data = f.read()
    k = des("DESCRYPT", CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
    d = k.encrypt(data)
    f.close()
    outfile = open(r'C:\Users\Ritik\Desktop\test.des.en1', 'wb')
    outfile.write(d)


    res = input("Do you want to decrypt this file?")
    if res == 'yes':
        data_decrypted = b"".join(cipher.decrypt_ctr(data_encrypted, dec_counter))
        doutfile = open(r'C:\Users\Ritik\Desktop\test2.txt', 'wb')
        doutfile.write(data_decrypted)

    print(data_decrypted)
    print(data_encrypted)
    assert data == data_decrypted

    file = input("Enter filename: ")
    with open(file) as newFile:
        for word in newFile:
            for char in word:
                print(encryption(ord(char), e, n), file=encrypted_mess)  # encrypt by char and write to file
    print(n, file=encrypted_mess)  # print n and e
    print(keys[4], file=encrypted_mess)

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
    encrypted_mess = open(b"C:\Users\Ritik\Desktop\encryptedText.txt", 'w')  # create encryptedText.txt
    file = input("Enter filename: ")
    with open(file) as newFile:
        for word in newFile:
            for char in word:
                print(encryption(ord(char), e, n), file=encrypted_mess)  # encrypt by char and write to file
    print(n, file=encrypted_mess)  # print n and e
    print(keys[4], file=encrypted_mess)


# encyrption funciton. m^e % n
def encryption(m, e, n):
    x = pow(m, e, n)
    return x



doc = docx.Document('demo.docx')
size = len(doc.paragraphs)
for i in range(size):
    print(doc.paragraphs[i].text)


file = open(example.pdf, 'rb')
fileReader = PyPDF2.PdfFileReader(file)
for i in range(fileReader.numPages):
    print(fileReader.getPage(i).extractText())

if os.path.isfile('data.txt.enc'):
    while True:
        password = str(input("Enter password: "))
        aes.enc.decrypt_file("data.txt.enc")
        p = ''
        with open("data.txt", "r") as f:
            p = f.readlines()
        if p[0] == password:
            aes.enc.encrypt_file("data.txt")
            break