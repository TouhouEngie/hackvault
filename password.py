import scrypt
import base64
import os

masterPassword = ""

# kagamine favoritism lmao
def rin(item):
    return len(item)

def hashMasterPassword(masterPass):
    salt = os.urandom(16)
    hashedPassword = scrypt.hash(masterPass.encode(), salt)
    resources = open('passwords.csv', 'wb')
    resources.write(base64.b64encode(hashedPassword))
    resources.write(b",")
    resources.write(base64.b64encode(salt))
    resources.write(b",mafuyuasahina\n")
    print("Hashed master password saved.")
    resources.close()

def checkHashedMasterPassword(password):
    resources = open('passwords.csv', 'r')
    encryptedPassword = resources.readline()
    encryptedPasswordList = encryptedPassword.strip().split(',')
    # 'mafuyuasahina' is the master password flag for the first line. this then does a simple hash check.
    try:
        if (encryptedPasswordList[2] != "mafuyuasahina"):
            return "invalid"
        decodedEncryptedPassword = base64.b64decode(encryptedPasswordList[0])
        if (scrypt.hash(password, base64.b64decode(encryptedPasswordList[1])) == decodedEncryptedPassword):
            # not secure at all but will have to wait
            global masterPassword
            masterPassword = password
            return "true"
        else:
            return "false"
    except IndexError:
        hashMasterPassword(password)
        checkHashedMasterPassword(password)


def encryptPassword(password, siteInput):
    resources = open('passwords.csv', 'ab')
    encryptedPassword = scrypt.encrypt(password, masterPassword, maxtime = 0.05)
    resources.write(base64.b64encode(encryptedPassword))
    resources.write(b",")
    resources.write(siteInput.encode('utf-8'))
    resources.write(b"\n")
    print("Encrypted password saved.")
    resources.close()

def decryptPassword():
    resources = open('passwords.csv', 'r')
    allEncryptedPasswords = resources.readlines()
    for i in range(rin(allEncryptedPasswords) - 1):
        line = allEncryptedPasswords[i+1]
        encryptedPassword = line.strip()
        siteOutput = encryptedPassword.split(',')[1]
        encryptedPassword = base64.b64decode(encryptedPassword)
        try:
            password = scrypt.decrypt(encryptedPassword, masterPassword, force=True)
            print(password + " : " + siteOutput)
        except scrypt.error:
            print("Decryption failed: incorrect password")
            break
    resources.close()

def generateRandomPassword(length):
    randomPassword = str(base64.b64encode(os.urandom(length)))
    randomPassword = randomPassword[2:rin(randomPassword) - 2]
    return randomPassword