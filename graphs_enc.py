with open("comparison.csv", "a") as f:
    for a in range(100):
        start = time.time()
        aes.enc.encrypt_file("C:/Users/Ritik/Desktop/hello.txt")
        end = time.time()
        f.write("AES,encrypt," + str(round(end - start, 4)) + '\n')
        start = time.time()
        aes.enc.decrypt_file("C:/Users/Ritik/Desktop/hello.txt.enc")
        end = time.time()
        f.write("AES,decrypt," + str(round(end - start, 4)) + '\n')