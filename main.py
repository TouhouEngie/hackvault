import scrypt
import base64
import sys
import os

def encryptPassword(password):
    resources = open('passwords.txt', 'ab')
    encryptedPassword = scrypt.encrypt(password, masterPassword, maxtime = 0.05)
    resources.write(base64.b64encode(encryptedPassword))
    resources.write(b"\n")
    print("Encrypted password saved.")
    resources.close()

def decryptPassword():
    resources = open('passwords.txt', 'r')
    for line in resources:
        encryptedPassword = line.strip()
        encryptedPassword = base64.b64decode(encryptedPassword)
        try:
            password = scrypt.decrypt(encryptedPassword, masterPassword, force=True)
            print(password)
        except scrypt.error:
            print("Incorrect password")
            break
    resources.close()

while True:
    masterPassword = input("Enter your master password: ")
    if (masterPassword != ""):
        break

while True:
    print("1. Encrypt a password...")
    print("2. Decrypt all passwords...")
    print("3. Change inputted master password...")
    print("4. Exit...")
    selection = input("Enter a selection: ")
    if (selection == "1"):
        pw = input("Enter a password you want to encrypt: ")
        encryptPassword(pw)
    elif (selection == "2"):
        decryptPassword()
    elif (selection == "3"):
        masterPassword = input("Enter your master password: ")
    elif (selection == "4"):
        sys.exit()
    else:
        print("Invalid selection.")

