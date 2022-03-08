#!/bin/python3
# ultron-server-beta

import socket
import shutil
import sys
import random
from datetime import datetime
import threading
import hashlib
import os
from os import scandir
import time
from cryptography.fernet import Fernet

class colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'

class cOP:
    size = "333"
    file = "334"
    fileend = "335"
    OK = "200"
    forbidden = "403"
    notfound = "404"
    chatroom = "808"
    upload = "300"
    download = "301"
    serverupdate = "302"
    ping = "303"
    backup = "304"
    sync = "305"
    listfs = "306"
    usertoken = "100"
    syn = "SYN"
    rst = "RST"
    sya = "SYA"
    ack = "ACK"

def write_log(log):
    with open('err_log.txt', 'a') as errFile:
        errFile.write(str(log))
    errFile.close()
    
def write_logcon(log):
    with open('conn_log.txt', 'a') as logFile:
        logFile.write(str(log))
    logFile.close()

class TCPServer:

    def __init__(self, host, port):
        self.host = host
        self.port = port
    
    def print_log(self, msg):
        current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f'[{current_date_time}] {msg}')
    
    def encrypt_data(self, fileData):
        with open('key.txt', 'rb') as keyFile:
            key = keyFile.read()
        keyFile.close()
        fernet = Fernet(key)
        encryptedData = fernet.encrypt(fileData)
        return encryptedData
    
    def decrypt_data(self, fileData):
        with open('key.txt', 'rb') as keyFile:
            key = keyFile.read()
        keyFile.close()
        fernet = Fernet(key)
        decryptedData = fernet.decrypt(fileData)
        return decryptedData

    def convert_date(self, timestamp):
        d = datetime.utcfromtimestamp(timestamp)
        formated_date = d.strftime('%d %b %Y')
        return formated_date

    def get_files(self):
        dir_entries = scandir('my_directory/')
        for entry in dir_entries:
            if entry.is_file():
                info = entry.stat()
                listfs = (f'{entry.name}\t Last Modified: {self.convert_date(info.st_mtime)}')
        return listfs
    
    def get_size(self, dir1):
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(dir1):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                # skip if it is symbolic link
                if not os.path.islink(fp):
                    total_size += os.path.getsize(fp)
        return total_size
    
    def token_gen(self):
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
                print(colors.RED, "Error: ", colors.WHITE, "could not generate session_token")
                sys.exit("\r\n")
        return token
    
    def authtoken_check(self, clientSock, clientAddr):
                clientToken = clientSock.recv(1024)
                clientToken = self.decrypt_data(clientToken)
                clientToken = clientToken.decode()
                clientToken = clientToken[0:30]
                self.print_log(f'fetching token from db for {clientAddr}')
                with open("valid_token.txt", "r") as vtFile:
                    tokens = vtFile.read()
                vtFile.close()
                count = len(tokens)
                num = count/30
                num_token = int(num)
                valid_token = [0, 0, 0, 0]
                x = 0
                x1 = 30
                for i in range(num_token):
                    valid_token[i] = tokens[x:x1]
                    x1 = x1 + 31
                    x = x + 31
                
                for i in range(num_token):
                    self.print_log(f'checking token integrity from {clientAddr}')
                    if valid_token[i] == clientToken:
                        return True
                    elif i + 1 == num_token:
                        return False
    
    def user_config(self, clientSock, clientAddr):
        clientToken = clientSock.recv(1024)
        clientToken = self.decrypt_data(clientToken)
        clientToken = clientToken.decode()
        clientToken = clientToken[0:30]
        self.print_log(f'fetching token from db for {clientAddr}')
        with open("valid_token.txt", "r") as vtFile:
            tokens = vtFile.read()
        vtFile.close()
        count = len(tokens)
        num = count/30
        num_token = int(num)
        valid_token = [0, 0, 0, 0]
        x = 0
        x1 = 30
        for i in range(num_token):
            valid_token[i] = tokens[x:x1]
            x1 = x1 + 31
            x = x + 31
    
        for i in range(num_token):
            self.print_log(f'checking token integrity from {clientAddr}')
            # debuginfo 
            # print(valid_token[i], "==", clientToken)
            if valid_token[i] == clientToken:
                self.print_log(f'token is valid from {clientAddr}')
                return i
            elif i + 1 == num_token:
                return False
    
    def check_dir(self, dirPath):
        if os.path.exists(str(dirPath)):
            self.print_log(f'Directory {dirPath} exists.')
        else:
            self.print_log(f'Directory {dirPath} not exists --> creating...')
            os.makedirs(dirPath)
    
    def handle_file(self, clientSock, clientAddr, fileDirectory):
        self.print_log(f'recieving file-info from {clientAddr}')
        # recieving fileName
        fileName = clientSock.recv(1024)
        fileName = self.decrypt_data(fileName)
        fileName = fileName.decode()
        fileFormat = fileName[-4:]
        self.print_log(f'recied fileName {fileName} from {clientAddr}')
        # recieving fileSize 
        fileSize = clientSock.recv(1024)
        fileSize = self.decrypt_data(fileSize)
        fileSize = fileSize.decode()
        self.print_log(f'recied fileSize {fileSize} from {clientAddr}')
        # recieving fileBytesSize
        fileBytesSize = clientSock.recv(1024)
        fileBytesSize = self.decrypt_data(fileBytesSize)
        fileBytesSize = fileBytesSize.decode()
        self.print_log(f'recieved fileBytesSize {fileBytesSize} from {clientAddr}')
        # recieving bytes from file
        self.print_log(f'recieving fileBytes from {clientAddr}')
        fragmentCount = 0
        fileData = ''
        fileBytesSize = int(fileBytesSize)
        if fileBytesSize > 1448:
            fragmentCount = fileBytesSize / 1448
            fragmentCount += 1
        else: 
            fragmentCount = 1
        self.print_log(f'recieving bytes in {int(fragmentCount)} fragments')
        for i in range(int(fragmentCount)):
            self.print_log(f'recieving fileBytes from {clientAddr}')
            fileBytes = clientSock.recv(1500)
            fileBytes = fileBytes.decode()
            fileData += fileBytes
            self.print_log(f'comparing size {fileBytesSize} == {len(fileData)}')
            if int(fileBytesSize) == int(len(fileData)):
                self.print_log(f'fileBytes recieved successfully from {clientAddr}')
                i = int(fragmentCount)
                break 
            else:
                self.print_log(f'fileBytes missing from {clientAddr}')
                pass
        self.print_log(f'decrypting and decoding bytes from {clientAddr}')
        fileData = fileData.encode()
        fileData = self.decrypt_data(fileData)
        specFileFormat = False
        time.sleep(0.2)
        if not specFileFormat:
            self.print_log(f'file recieved from {clientAddr} with {len(fileData)} bytes. writing to directory')
            with open(fileDirectory + fileName, 'wb') as openFile:
                openFile.write(fileData)
            openFile.close()
            self.print_log(f'file from {clientAddr} written to {fileDirectory + fileName}')
        fileSize = int(fileSize)
        self.print_log(f'comparing fileSize {fileSize} == {len(fileData)}')
        if fileSize == len(fileData):
            self.print_log(f'filesize OK. sending answer to {clientAddr}')
            clientSock.send(cOP.OK.encode())
        else:
            message = 'server_side_error occurred. please try upload again.'
            error = f'fileSize comparing failed. sending answer to {clientAddr}'
            write_log(error)
            self.print_log(error)
            clientSock.send(message.encode())
            clientSock.close()

    def handling_options(self, clientSock, clientAddr, data):
            data = data.decode()
            userArray = ["", "", "", ""]
            if data == cOP.backup:
                userID = self.user_config(clientSock, clientAddr)
                fileTransfer = True
                global isDir
                if not userID and userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.forbidden.encode())
                    clientSock.close()
                else:
                    clientSock.send(cOP.OK.encode())
                    self.print_log(f'preparing backup from {clientAddr}')
                    # recieving destDirectory
                    self.print_log(f'recieving Directory from {clientAddr}')
                    destDir = clientSock.recv(1024) 
                    destDir = self.decrypt_data(destDir)
                    destDir = destDir.decode()
                    destDir = destDir + '/'
                    isDir = False
                    # getting dirSizeBefore
                    self.check_dir(userArray[userID] + destDir)
                    dirSizeBefore = self.get_size(userArray[userID] + destDir)
                    # recieving backupsize
                    self.print_log(f'recieving backup-size from {clientAddr}')
                    backupSize = clientSock.recv(2048)
                    backupSize = self.decrypt_data(backupSize)
                    backupSize = backupSize.decode()
                    # recieving backup
                    while fileTransfer:
                        # recieving fileTransfer status 
                        if not isDir:
                            self.print_log(f'recieving fileTransferStatus from {clientAddr}')
                            status = clientSock.recv(1024)
                            status = status.decode()
                        else:
                            pass
                        global dirName
                        if status == cOP.backup:
                            self.print_log(f'recieving fileDirectoryName from {clientAddr}')
                            # recieving directory name
                            dirName = clientSock.recv(1024)
                            dirName = self.decrypt_data(dirName)
                            dirName = dirName.decode()
                            # checking Directory
                            self.check_dir(userArray[userID] + destDir + dirName)
                            self.print_log(f'recieving fileRequestOperand from {clientAddr}')
                            req = clientSock.recv(1024)
                            req = req.decode()
                            if req == cOP.file:
                                isDir = False
                                self.handle_file(clientSock, clientAddr, userArray[userID] + destDir + dirName)
                            elif req == cOP.backup:
                                self.print_log(f'recieved fileTransferStatus from {clientAddr}')
                                isDir = True 
                                # self.print_log(f'no file in {dirName} from {clientAddr}')
                            else:
                                self.print_log(req)
                        elif status == cOP.file:
                            self.handle_file(clientSock, clientAddr, userArray[userID] + destDir + dirName)              
                        elif status == cOP.OK:
                            userDir = userArray[userID] + destDir
                            currSize = self.get_size(userDir)
                            if currSize == dirSizeBefore:
                                actSize = backupSize
                            else:
                                actSize = currSize - dirSizeBefore
                            # print(f'{currSize} - {dirSizeBefore}')
                            # actSize = int(actSize) - int(dirSizeBefore)
                            self.print_log(f'checking directories {userDir} and {destDir}')
                            self.print_log(f'recieved status OK from {clientAddr}: recieving bytes {actSize}/{backupSize}')
                            if int(backupSize) == int(actSize):
                                fileTransfer = False
                                self.print_log(f'file transfer finished from {clientAddr}')
                                clientSock.send(cOP.OK.encode())
                                clientSock.close()
                            else:
                                fileTransfer = False
                                message = f'server_side_error: endCheck failed. try backup again.'
                                clientSock.send(message.encode())
                                self.print_log(f'server_side_error: close connection to {clientAddr}')
                                clientSock.close()
                        else:
                            self.print_log(f'closing connection to {clientAddr}: closed by cient')
                            fileTransfer = False
                            clientSock.close()                                           
            elif data == cOP.chatroom:
                pass
            elif data == cOP.download:
                done = False
                userID = self.user_config(clientSock, clientAddr)
                if not userID and userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.forbidden.encode())
                    clientSock.close()
                else:
                    clientSock.send(cOP.OK.encode())
                    fileName = clientSock.recv(1024)
                    fileName = self.decrypt_data(fileName)
                    fileName = fileName.decode()
                    self.print_log(f'searching requestet file for {clientAddr}')
                    for dirpath, dirnames, files in os.walk(userArray[userID], topdown=False):
                        for file_name in files:
                            if file_name == fileName:
                                self.print_log(f'file found. sending to client {clientAddr}')
                                clientSock.send(cOP.OK.encode())
                                filePath = dirpath+ "/" + file_name
                                with open(filePath, 'rb') as clientFile:
                                    data = clientFile.read()
                                clientFile.close()
                                data = self.encrypt_data(data)
                                fileSize = len(data)
                                fileSize = str(fileSize).encode()
                                fileSize = self.encrypt_data(fileSize)
                                clientSock.send(fileSize)
                                time.sleep(0.2)
                                clientSock.send(data)
                                self.print_log(f'waiting for response from {clientAddr}')
                                resp = clientSock.recv(1024)
                                if resp.decode() == cOP.OK:
                                    self.print_log(f'OK recieved. closing connection to {clientAddr}')
                                    clientSock.close()
                                    done = True
                                    break
                                else: 
                                    self.print_log(f'no response from {clientAddr}: closing connection')
                                    clientSock.close()
                                    done = True
                                    break
                    if done:
                        pass
                    else:
                        self.print_log(f'closing connection to {clientAddr}: could not locate file')
                        clientSock.send(cOP.rst.encode())
                        clientSock.close()
            elif data == cOP.listfs:
                listfs = ''
                userID = self.user_config(clientSock, clientAddr)
                if not userID and userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.rst.encode())
                    clientSock.close()
                else:
                    clientSock.send(cOP.OK.encode())
                    cut = len(userArray[userID])
                    for dirpath, dirnames, files in os.walk(userArray[userID], topdown=False):
                        listfs = listfs + (f' Directory: {dirpath[cut-1:]} \r\n')
                        for file_name in files:
                            listfs = listfs + (f'    \'----------> {file_name}\r\n')
                    self.print_log(f'sending filesystem to {clientAddr}')
                    time.sleep(0.2)
                    listfs = listfs.encode()
                    listfs = self.encrypt_data(listfs)
                    fileSize = len(listfs)
                    fileSize = str(fileSize).encode()
                    fileSize = self.encrypt_data(fileSize)
                    clientSock.send(fileSize)
                    time.sleep(0.2)
                    clientSock.send(listfs)
                    self.print_log(f'waiting for OK from {clientAddr}')
                    recv = clientSock.recv(1024)
                    if recv.decode() == cOP.OK :
                        self.print_log(f'OK recieved. closing connection to {clientAddr}')
                        clientSock.close()                
            elif data == cOP.ping:
                clientSock.send(cOP.OK.encode())
                ping = f'sending ping request to {clientAddr}'
                write_log(ping)
                self.print_log(ping)
                self.print_log(f'closed connection to {clientAddr}')
                clientSock.close()
            elif data == cOP.rst:
                pass
            elif data == cOP.serverupdate:
                with open('UCB.py', 'r') as file:
                    data = file.read()
                file.close()
                fileSize = os.path.getsize('UCB.py')
                fileSize = str(fileSize).encode()
                fileSize = self.encrypt_data(fileSize)
                clientSock.send(fileSize)
                data = data.encode()
                data = self.encrypt_data(data)
                clientSock.send(data)
                updatedb = f'sending update to {clientAddr}: closing connection'
                write_log(updatedb)
                self.print_log(updatedb)
                clientSock.close()
            elif data == cOP.upload:
                userID = self.user_config(clientSock, clientAddr)
                if not userID and userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.forbidden.encode())
                    clientSock.close()
                else:
                    clientSock.send(cOP.OK.encode())
                    self.print_log(f'recieving file from {clientAddr}')
                    fragmentCount = 0
                    fileDir = clientSock.recv(1024)
                    fileDir = self.decrypt_data(fileDir)
                    fileDir = fileDir.decode()
                    self.print_log(f'recieved filedirectory from {clientAddr}')
                    fileData = ''
                    time.sleep(0.1)
                    filesize = clientSock.recv(1024)
                    filesize = self.decrypt_data(filesize)
                    filesize = filesize.decode()
                    filesize = int(filesize)
                    self.print_log(f'recieved filesize from {clientAddr}')
                    recieved = False
                    if filesize > 1448:
                        fragmentCount = filesize / 1448
                        fragmentCount += 1
                    else:
                        fragmentCount = 1
                    for i in range(int(fragmentCount)):
                        fileBytes = clientSock.recv(1500)
                        fileBytes = fileBytes.decode()
                        fileData += fileBytes
                        self.print_log(f'recieving bytes: {len(fileData)}/{filesize}')
                        if filesize == len(fileData):
                            self.print_log(f'recieved bytes successfully from {clientAddr}')
                            recieved = True
                    fileData = fileData.encode()
                    fileData = self.decrypt_data(fileData)
                    filePath = userArray[userID] + fileDir 
                    with open(filePath, 'wb') as openFile:
                        openFile.write(fileData)
                    openFile.close()
                    if recieved:
                        self.print_log(f'file from {clientAddr} written to  {filePath}')
                        clientSock.send(cOP.OK.encode())
                        clientSock.close()
                    else:
                        self.print_log(f'filesize comparison went wrong. ERROR in {filesize}=={os.path.getsize(filePath)}. closing connection to {clientAddr}')
                        clientSock.send(cOP.rst.encode())
                        clientSock.close()                   
            elif data == cOP.usertoken:
                if self.authtoken_check(clientSock, clientAddr):
                    clientSock.send(cOP.OK.encode())
                    self.print_log(f'closing connection to {clientAddr}: job done')
                    clientSock.close()
                else:
                    clientSock.send(cOP.rst.encode())
                    error = f'closing connection to {clientAddr}: token invalid'
                    write_log(error)
                    self.print_log(error)
                    clientSock.close()                       
            else:
                clientSock.send(cOP.rst.encode())
                self.print_log(f'closed connection to {clientAddr}: wrong operand')
                clientSock.close()
    def configure_server(self):
        self.print_log('starting server...')
        self.print_log('creating socket...')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.print_log('socket created successfully')
        self.sock.bind((self.host, self.port))
        self.print_log(f'server listening on {self.host} :: {self.port}')    
    def client_connections(self):
        try:
            self.sock.listen(10)
            while True:
                clientSock, clientAddr = self.sock.accept()
                self.print_log(f'recieved request from {clientAddr}')
                current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log = f'[{current_date_time}] recv conn from: {clientAddr}'
                write_logcon(log)
                clientThread = threading.Thread(target=self.handle_client,
                                                    args = (clientSock, clientAddr))
                clientThread.start()
        except KeyboardInterrupt:
            self.shutdown_server()
        except Exception as error:
           self.print_log(error)
           write_log(error)
           sys.exit()   
    
    def hashing_fct(self, hashString):
        shaSignature = hashlib.sha256(hashString.encode()).hexdigest()
        shaSignature = hashlib.sha256(hashString.encode()).hexdigest()
        return shaSignature

    def token_check(self, recvToken, token):
        if recvToken.decode() == token:
            return True
        else:
            return False
        
    def handle_client(self, clientSock, clientAddr):
        try:
            self.print_log(f'waiting for request from {clientAddr}')
            option = clientSock.recv(1024)
            self.print_log(f'request recieved from {clientAddr}')
            self.handling_options(clientSock, clientAddr, option)

        except KeyboardInterrupt:
            sys.exit("^C")        
        except Exception as error:
            print(error)
            write_log(error)

    def start_server(self):
        try: 
            self.client_connections()
        except KeyboardInterrupt:
            self.shutdown_server()
        except Exception as error:
            self.print_log(error)
            write_log(error)
            sys.exit()

    def shutdown_server(self):
        self.print_log('shutting down server...')
        self.sock.close()

def start_server():
    # vars 
    #if sys.arv[1] in ("--h", "--t"
    if len(sys.argv) == 5 or sys.argv[1] == '--updatedb':
        if sys.argv[1] == "--a":
            host = sys.argv[2]
        elif sys.argv[1] == "--updatedb":
            try:
                shutil.copy("USB.py", "/run/media/ryx/Volume/programming/ultron_server/")
                shutil.copy("UCB.py", "/run/media/ryx/Volume/programming/ultron_server/")
                shutil.copy("valid_token.txt", "/run/media/ryx/Volume/programming/ultron_server/")
                shutil.copy("key.txt", "/run/media/ryx/Volume/programming/ultron_server/")
            except Exception as error:
                print(colors.RED + error + colors.White)
            print("updated succesfully")
            sys.exit()
        if sys.argv[3] == "--p":
            port = sys.argv[4]
        else:
            print('ultron_server_beta | usage: ./USB.py --a [ADDRESS] --p [PORT]')
            sys.exit()
    else:
        print('ultron_server_beta | usage: ./USB.py --a [ADDRESS] --p [PORT]')
        sys.exit()

    server = TCPServer(host, int(port))
    server.configure_server()
    server.start_server()
  
try:
    start_server()
except Exception as e:
    error = f'{colors.RED}SERVER_ERROR: {e}{colors.WHITE}' 
    write_log(str(error))
    sys.exit(error)


 
