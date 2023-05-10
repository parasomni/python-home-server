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
valid_tokens = '/etc/ultron-server/valid-tokens.txt'
token = ''
check_dir(ultron_path)

if os.path.exists(key_path):
    os.system(f'mv {key_path} {ultron_path}prvt.key')
elif os.path.exists(ultron_path + 'prvt.key'):
    print(f'private key found: {ultron_path}prvt.key')
    pass
else:
    key = Fernet.generate_key()
    print('private key generated')
    with open(ultron_path + 'prvt.key', 'wb') as file:
        file.write(key)
    file.close()
    print(f'private key written to {ultron_path}prvt.key')
if os.path.exists(token_path):
    os.system(f'mv {token_path} {ultron_path}token.txt')
elif os.path.exists(ultron_path + 'token.txt'):
    print(f"token found: {ultron_path}token.txt")
    pass
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
try:
    token = token.decode()
except Exception:
    pass
token = str(token) + '\r\n'
with open(valid_tokens, 'a') as f:
    f.write(str(token))
f.close()
print(f'updated file {valid_tokens}')

print("\r\n---server configuration---")
print("please set the user path the client can access to")
client1 = input("client 1:")
client2 = input("client 2:")
client3 = input("client 3:")
client4 = input("client 4:")
config = f"""
# server configuration

# Indicates the client paths
        ,{client1},
        ,{client2},
        ,{client3},
        ,{client3},

# Indicates the private key
        ,/etc/ultron-server/prvt.key,

# Indicates the vaild token file path
        ,/etc/ultron-server/valid-tokens.txt,


"""
with open (ultron_path + 'server.cfg', 'w') as f:
    f.write(config)
f.close()
print(config)
print('---server configuration---\r\n')
print('setting up triggers')
os.system('cp us-v1.1.4-stable.py /usr/bin/us')
os.system('chmod +x /usr/bin/us')
