import sys
import password

while True:
    masterPassword = input("Enter your master password: ")
    if password.checkHashedMasterPassword(masterPassword) == "invalid":
        password.hashMasterPassword(masterPassword)
    elif password.checkHashedMasterPassword(masterPassword) == "false":
        print("incorrect password")
        continue
    else:
        break

while True:
    print("1. Encrypt a password...")
    print("2. Decrypt all passwords...")
    print("3. Generate a random password...")
    print("4. Exit...")
    selection = input("Enter a selection: ")
    if (selection == "1"):
        pw = input("Enter a password you want to encrypt (blank for a randomly generated password): ")
        if (pw == ""):
            pw = password.generateRandomPassword(12)
            print('Your randomly generated password is: ' + pw)
        site = input("Enter the URL of the website you want to use the password for: ")
        password.encryptPassword(pw, site)
    elif (selection == "2"):
        password.decryptPassword()
    elif (selection == "3"):
        print(password.generateRandomPassword(12))
    elif (selection == "4"):
        sys.exit()
    else:
        print("Invalid selection.")

