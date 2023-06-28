#!/usr/bin/python3
# integrity script for ultron_server
# version 1.0.2

import hashlib
import sys
import os

class colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'

def check_dir(dirPath, x):
        if os.path.exists(str(dirPath)):
            print(f'found file {dirPath}')
            return f_hashing(dirPath)
        else:
            print(colors.RED, f'ERROR: File {dirPath} not exists.', colors.WHITE)
            return False

def hash_function(hashString):
    # hashes a string
    hashString = str(hashString)
    hashedString = hashlib.sha256(hashString.encode()).hexdigest()
    return hashedString

def find(name, path):
    # find names in a path
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)

def write_file(hash_str, txt_path_):
    # writing hashes to text file
    with open(txt_path_, "a") as f:
        f.write(hash_str)
    f.close()

def find_files():
    hash_string = ['', '', '', '']
    print('searching files')
    # find files in the given path
    fileArray = [
    '/etc/ultron-server/key.txt',
    '/etc/ultron-server/token.txt',
    '/etc/ultron-server/valid_token.txt'
    ]
    for i in range(4):
        hash_string[i] = check_dir(fileArray[i], i)
        if not hash_string[i]:
            hash_string[i] = 'A'*64
    cmp_hashes(hash_string[0], hash_string[1], hash_string[2], hash_string[3],
            fileArray[0], fileArray[1], fileArray[2], fileArray[3])

def f_hashing(filePath):
    # hashing the given file
    with open(filePath, 'rb') as fileRead:
        fileBytes = fileRead.read()
    fileRead.close()
    for i in range(1328):
        # hashing file with 1328 iterations for more safety
        fileBytes = hash_function(fileBytes)
    print(f'created hash for {filePath}')
    return fileBytes

def cmp_hashes(h1, h2, h3, h4, f1, f2, f3, f4):
    hash_string = [h1, h2, h3, h4]
    fileArray = [f1, f2, f3, f4]
    digit1 = 0
    digit2 = 64
    for x in range (4):
        hashHash = hash_string[x]
        if not os.path.exists('/etc/ultron-server/hashes.txt'):
            print('hash file not exists. writing hashes to hashfile...')
            fin_hash = ''
            for a in range (4):
                hash_string[a] += ','
                fin_hash += hash_string[a]
            with open('/etc/ultron-server/hashes.txt', 'a') as hashFile:
                hashFile.write(fin_hash)
            hashFile.close()
            print('job done. quitting')
            sys.exit()
        else:
            print('collecting hashes from hashfile...')
            with open('/etc/ultron-server/hashes.txt', 'r') as hashFile:
                hashes = hashFile.read()
            hashFile.close()
            for i in range (10):
                hashes = hashes.replace(',', '')
            print('comparing hashes...')
            hash = hashes [digit1:digit2]
            if hashHash == hash:
                print('comparing hashes', colors.GREEN, 'successfull', colors.WHITE)
                print(f'--> file {fileArray[x]} {colors.GREEN} valid {colors.WHITE}')
            else:
                print('comparing hashes', colors.RED, 'failed', colors.WHITE)
                print(f'HF:{hash} == CH:{hashHash}')
                print(f'--> file {fileArray[x]} {colors.RED} invalid {colors.WHITE}')
            digit1 += 64
            digit2 += 64

def main():
    print('collecting information...')
    ultronPath = read_config()
    find_files()
    print('job done. quitting')

try: 
    main()
except Exception as error:
    print(colors.RED, error, colors.WHITE)
    sys.exit

    

      
    
        
