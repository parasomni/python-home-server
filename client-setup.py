#!/usr/bin/python3

from cryptography.fernet import Fernet
import sys
import random
import os

def token_gen():
        upperCase = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
                    "U", "V", "W", "X", "Y", "Z"]
        lowerCase = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
                    "u", "v", "w", "x", "y", "z"]
        nNumbers = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
        specialChars = ["\"", "{", "}", ".", ",", ";", "/", "\\", "<", ">", "=", "[", "]", "^", "~", "_",
                        "|", "%", "&", "'", "`", "@", "*", "-", "#", "+", "$", "!", ":", "?"]
        token = ""
        for i in range(30):
            r1 = random.randint(1, 4)
            if r1 == 1:
                r2 = random.randint(0, 25)
                token += upperCase[r2]
            elif r1 == 2:
                r2 = random.randint(0, 25)
                token += lowerCase[r2]
            elif r1 == 3:
                r2 = random.randint(0, 9)
                token += nNumbers[r2]
            elif r1 == 4:
                r2 = random.randint(0, 28)
                token += specialChars[r2]
            else:
                print("Error: could not generate session_token")
                sys.exit("\r\n")
        return token

def check_dir(dirPath):
        if os.path.exists(str(dirPath)):
                print(f'Directory {dirPath} exists.')
                pass
        else:
                print(f'Directory {dirPath} not exists --> creating...')
                os.makedirs(dirPath)

key_path = os.getcwd() + '/key.txt'
token_path = os.getcwd() + '/token.txt'
ultron_path = '/etc/ultron-server/'
check_dir(ultron_path)

if os.path.exists(key_path):
        os.system(f'mv {key_path} {ultron_path}key.txt')
else:
        key = Fernet.generate_key()
        print('private key generated')
        with open(ultron_path + 'key.txt', 'wb') as file:
                file.write(key)
        file.close()
print(f'private key written to {ultron_path}key.txt')
if os.path.exists(token_path):
        os.system(f'mv {token_path} {ultron_path}token.txt')
else:
        token = token_gen()
        print('user token generated')
        str1 = token + '\r\n'
        str1 = str1.encode()
        token = token.encode()
        with open('token.txt', 'wb') as file:
            file.write(token)
        file.close()
print(f'user-token written to {ultron_path}token.txt')
print('setting up triggers')
os.system('cp uc-v1.1.4-stable.py /usr/bin/uc')
os.system('chmod +x /usr/bin/uc')
