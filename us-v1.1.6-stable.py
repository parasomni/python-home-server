#!/usr/bin/python3
# version 1.1.6

# upcomming improvements:
# file checker » if file is already downloaded only new files will be downloaded

# import required modules
import socket
import shutil
import smtplib
import sys
import threading
import os
import time

from datetime import datetime
from cryptography.fernet import Fernet
from http import client
from email import encoders
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart


# class for colored output
class colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'

# necessary oparands for communication between client and server
class cOP:
    size = "333"
    file = "334"
    directory = "336"
    fileend = "335"
    transfer = "340"
    OK = "200"
    forbidden = "403"
    notfound = "404"
    chatroom = "808"
    upload = "300"
    remove = "299"
    download = "301"
    serverupdate = "302"
    ping = "303"
    backup = "304"
    sync = "305"
    listfs = "306"
    grep = "307"
    usertoken = "100"
    syn = "SYN"
    rst = "RST"
    sya = "SYA"
    ack = "ACK"
    package = "310"
    listall = "311"
    encrypt = "000"
    decrypt = "999" 
    search = "876"

def check_dir(dirPath):
    if os.path.exists(str(dirPath)):
        pass
    else:
        os.makedirs(dirPath)

# error logging
def write_log(log):
    current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log = f'[{current_date_time}] {log}'
    with open('/etc/ultron-server/err_log.txt', 'a') as errFile:
        errFile.write(str(log) + '\r\n')
    errFile.close()

# connection logging
def write_logcon(log):
    with open('/etc/ultron-server/conn_log.txt', 'a') as logFile:
        logFile.write(str(log) + '\r\n')
    logFile.close()

# DDoS logging    
def write_ddos_log(log):
    with open('/etc/ultron-server/ddos_log.txt', 'a') as logFile:
        logFile.write(str(log) + '\r\n')
    logFile.close()

# log client actions
def server_log(client, log):
    current_date = datetime.now
    date = current_date.day + current_date.month + current_date.year
    client_server_path = '/etc/ultron-server/' + client.split('/')[-1];
    check_dir(client_server_path) 
    with open(client_server_path + date + '.txt', 'a') as log_file:
        log_file.write(str(log)+ '\r\n')
    log_file.close()

# server main log
def server_main_log(log):
    server_main_log_path = '/etc/ultron-server/main-logs/'
    current_date = datetime.now
    date = current_date.day + current_date.month + current_date.year
    current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log = f'[{current_date_time}] {log}'
    check_dir(server_main_log_path)
    with open(server_main_log_path + date + '.txt', 'a') as log_file:
        log_file.write(str(log) + '\r\n')
    log_file.close()
    

# server implementation
class TCPServer:
    # initialize server
    def __init__(self, host, port):
        # load configuration
        with open('/etc/ultron-server/server.cfg') as configFile:
            ultronConfig = configFile.read()
        configFile.close()
        comma = ','
        commaPos = []
        for pos, char in enumerate(ultronConfig):
            if (char == comma):
                commaPos.append(pos)
        
        # set configuration 
        self.client1 = str(ultronConfig[commaPos[0]+1:commaPos[1]])
        self.client2 = str(ultronConfig[commaPos[2]+1:commaPos[3]])
        self.client3 = str(ultronConfig[commaPos[4]+1:commaPos[5]])
        self.client4 = str(ultronConfig[commaPos[6]+1:commaPos[7]])
        self.keyfile = str(ultronConfig[commaPos[8]+1:commaPos[9]])
        self.validtoken = str(ultronConfig[commaPos[10]+1:commaPos[11]])
        self.time_delay = float(ultronConfig[commaPos[12]+1:commaPos[13]])
        self.max_conn_number_ddos = int(ultronConfig[commaPos[14]+1:commaPos[15]])
        self.userEmail = str(ultronConfig[commaPos[16]+1:commaPos[17]])
        self.targetEmail = str(ultronConfig[commaPos[18]+1:commaPos[19]])
        self.creditFile = str(ultronConfig[commaPos[20]+1:commaPos[21]])
        self.host = host
        self.port = port
        self.total_con = 0
        self.ddos_protection_active = False

    # print log to stdout
    def print_log(self, msg):
        current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f'[{current_date_time}] {msg}')

    # encrypts data for communication
    def encrypt_data(self, fileData):
        with open(self.keyfile, 'rb') as keyFile:
            key = keyFile.read()
        keyFile.close()
        fernet = Fernet(key)
        encryptedData = fernet.encrypt(fileData)
        return encryptedData

    # decrypts data for communication
    def decrypt_data(self, fileData):
        with open(self.keyfile, 'rb') as keyFile:
            key = keyFile.read()
        keyFile.close()
        fernet = Fernet(key)
        decryptedData = fernet.decrypt(fileData)
        return decryptedData

    # formating of current date time for output
    def convert_date(self, timestamp):
        d = datetime.fromtimestamp(timestamp)
        formated_date = d.strftime('%d %b %Y')
        return formated_date

    # check if directory already exists    
    def check_dir(self, dirPath):
        if os.path.exists(str(dirPath)):
            self.print_log(f'Directory {dirPath} exists.')
            pass
        else:
            self.print_log(f'Directory {dirPath} not exists --> creating...')
            os.makedirs(dirPath)

    # returns size of directory
    def get_size(self, dir1):
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(dir1):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                # skip if it is symbolic link
                if not os.path.islink(fp):
                    total_size += os.path.getsize(fp)
        return total_size

    # check if tokens are equal
    def token_check(self, recvToken, token):
        if recvToken.decode() == token:
            return True
        else:
            return False
        
    # verification of authentification token
    def authtoken_check(self, clientSock, clientAddr):
                clientToken = clientSock.recv(1024)
                clientToken = self.decrypt_data(clientToken)
                clientToken = clientToken.decode()
                clientToken = clientToken[0:30]
                self.print_log(f'fetching token from db for {clientAddr}')
                with open(self.validtoken, "r") as vtFile:
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
                self.print_log(f'checking token integrity from {clientAddr}')
                for i in range(num_token):
                    if valid_token[i] == clientToken:
                        return True
                    elif i > num_token:
                        return False

    # identifies authenticated user
    def user_config(self, clientSock, clientAddr):
        # token verification
        clientToken = clientSock.recv(1024)
        clientToken = self.decrypt_data(clientToken)
        clientToken = clientToken.decode()
        clientToken = clientToken[0:30]
        self.print_log(f'fetching token from db for {clientAddr}')
        with open(self.validtoken, "r") as vtFile:
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
                self.print_log(f'token is valid from {clientAddr}')
                return i
            elif i > num_token:
                i = ''
                return i

    # checks if directory exists
    def fetch_dir(self, uploadFile):
        slashPos = []
        slashSym = '/'
        for pos, char in enumerate(uploadFile):
            if (char == slashSym):
                slashPos.append(pos)
        slashCount = len(slashPos) -1
        if slashCount >= 1:
            slashPosx = slashPos[slashCount]
            fileDir = uploadFile[0:slashPosx]
        else:
            fileDir = 'not available'
        return fileDir
    
    # file handling
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
        while True:
            self.print_log(f'recieving fileBytes from {clientAddr}')
            fileBytes = clientSock.recv(1024).decode()
            fileData += fileBytes
            self.print_log(f'recieving bytes: {len(fileData)}/{fileSize}')
            if int(fileBytesSize) == int(len(fileData)):
                self.print_log(f'fileBytes recieved successfully from {clientAddr}')
                break
            else:
                self.print_log(f'fileBytes missing from {clientAddr}')
                pass     
        # decrypting and decoding data
        self.print_log(f'decrypting and decoding bytes from {clientAddr}')
        fileData = fileData.encode()
        fileData = self.decrypt_data(fileData)
        specFileFormat = False
        time.sleep(self.time_delay)       
        # writing file
        if not specFileFormat:
            self.print_log(f'file recieved from {clientAddr} with {len(fileData)} bytes. writing to directory')
            with open(fileDirectory + fileName, 'wb') as openFile:
                openFile.write(fileData)
            openFile.close()
            self.print_log(f'file from {clientAddr} written to {fileDirectory + fileName}')
        fileSize = int(fileSize)
        self.print_log(f'comparing fileSize {fileSize} == {len(fileData)}')
        # sending finish and closing socket
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
    
    def send_package():
        pass
    
    # main function of request handling
    def handling_options(self, clientSock, clientAddr, data):
            # decoding request
            data = data.decode()
            userArray = [self.client1, self.client2, self.client3, self.client4]           
            # backup request
            if data == cOP.backup:           
                # user identification --> necessary for client system path
                userID = self.user_config(clientSock, clientAddr)
                fileTransfer = True
                global isDir         
                if userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.forbidden.encode())
                    clientSock.close()
                else:
                    clientSock.send(cOP.OK.encode())
                    log = f'preparing backup from {clientAddr}'
                    server_log(userArray[userID], log)
                    self.print_log(log)                  
                    # recieving destDirectory
                    log = f'recieving Directory from {clientAddr}'
                    server_log(userArray[userID], log) 
                    self.print_log(log)
                    destDir = clientSock.recv(1024)
                    destDir = self.decrypt_data(destDir)
                    destDir = destDir.decode()
                    isDir = False                  
                    # recieving backupsize
                    log = f'recieving backup-size from {clientAddr}'
                    server_log(userArray[userID], log) 
                    self.print_log(log)
                    backupSize = clientSock.recv(2048)
                    backupSize = self.decrypt_data(backupSize)
                    backupSize = backupSize.decode()
                    log = f'recieving directory name from {clientAddr}'
                    server_log(userArray[userID], log) 
                    self.print_log(log)                 
                    # getting dirSizeBefore
                    first_dir_name = clientSock.recv(2048)
                    first_dir_name = self.decrypt_data(first_dir_name)
                    first_dir_name = first_dir_name.decode()
                    self.check_dir(userArray[userID] + destDir)
                    dirSizeBefore = self.get_size(userArray[userID] + destDir + first_dir_name)                                     
                    # recieving backup
                    while fileTransfer:
                        # recieving fileTransfer status
                        if not isDir:
                            log = f'recieving fileTransferStatus from {clientAddr}'
                            server_log(userArray[userID], log) 
                            self.print_log(log)
                            status = clientSock.recv(1024)
                            status = status.decode()
                        else:
                            pass
                        global dirName                     
                        # backup ongoing
                        if status == cOP.backup:
                            log = f'recieving fileDirectoryName from {clientAddr}'
                            server_log(userArray[userID], log)                             
                            self.print_log(log)                         
                            # recieving directory name
                            dirName = clientSock.recv(1024)
                            dirName = self.decrypt_data(dirName)
                            dirName = dirName.decode()                         
                            # checking Directory
                            log = f'recieving fileRequestOperand from {clientAddr}'
                            self.check_dir(userArray[userID] + destDir + dirName)
                            server_log(userArray[userID], log) 
                            self.print_log(log)
                            req = clientSock.recv(1024)
                            req = req.decode()
                            if req == cOP.file:
                                isDir = False
                                self.handle_file(clientSock, clientAddr, userArray[userID] + destDir + dirName)
                            elif req == cOP.backup:
                                log = f'recieved fileTransferStatus from {clientAddr}'
                                server_log(userArray[userID], log) 
                                self.print_log(log)
                                isDir = True
                            else:
                                server_log(userArray[userID], req) 
                                self.print_log(req)                              
                        # backup ongoing -> receiving file        
                        elif status == cOP.file:
                            self.handle_file(clientSock, clientAddr, userArray[userID] + destDir + dirName)
                        # backup complete    
                        elif status == cOP.OK:
                            userDir = userArray[userID] + destDir + dirName
                            currSize = self.get_size(userDir)                           
                            # check that there was no data loss
                            if currSize == dirSizeBefore:
                                actSize = backupSize
                            else:
                                actSize = currSize - dirSizeBefore
                            log = f'checking directories {userDir} and {destDir}'
                            server_log(userArray[userID], log) 
                            self.print_log(log)
                            log = f'recieved status OK from {clientAddr}: recieving bytes {actSize}/{backupSize}'
                            server_log(userArray[userID], log) 
                            self.print_log(log)                           
                            if int(backupSize) == int(actSize):
                                # transfer finished
                                fileTransfer = False
                                log = f'file transfer finished from {clientAddr}'
                                server_log(userArray[userID], log) 
                                self.print_log(log)
                                clientSock.send(cOP.OK.encode())
                                clientSock.close()
                            else:
                                # transfer incomplete
                                fileTransfer = False
                                message = f'server_side_error: endCheck failed. try backup again.'
                                clientSock.send(message.encode())
                                log = f'server_side_error: close connection to {clientAddr}'                                
                                server_log(userArray[userID], log) 
                                self.print_log(log)
                                clientSock.close()
                        else:
                            log = f'closing connection to {clientAddr}: closed by cient'
                            server_log(userArray[userID], log) 
                            self.print_log(log)
                            fileTransfer = False
                            clientSock.close()           
            # download request                
            elif data == cOP.download:
                done = False              
                # user identification --> necessary for client system path                
                userID = self.user_config(clientSock, clientAddr)
                if userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.forbidden.encode())
                    clientSock.close()
                else:
                    clientSock.send(cOP.OK.encode())
                    transferType = clientSock.recv(1024)
                    transferType = transferType.decode()                  
                    # download file
                    if transferType == cOP.file:
                        # receiving file name
                        clientSock.send(cOP.OK.encode())
                        fileName = clientSock.recv(1024)
                        fileName = self.decrypt_data(fileName)
                        fileName = fileName.decode()                      
                        # search if file does exist
                        log = f'searching requestet file for {clientAddr}'
                        server_log(userArray[userID], log) 
                        self.print_log(log)
                        for dirpath, dirnames, files in os.walk(userArray[userID], topdown=False):
                            for file_name in files:
                                # file found
                                if file_name == fileName:
                                    log = f'file found. sending to client {clientAddr}'
                                    server_log(userArray[userID], log) 
                                    self.print_log(log)                                  
                                    # reading file data and sending to client
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
                                    time.sleep(self.time_delay)
                                    clientSock.send(data)
                                    log = f'waiting for response from {clientAddr}'
                                    server_log(userArray[userID], log) 
                                    self.print_log(log)
                                    resp = clientSock.recv(1024)                                   
                                    # check for data loss
                                    if resp.decode() == cOP.OK:
                                        log = f'OK recieved. closing connection to {clientAddr}'
                                        server_log(userArray[userID], log)                                         
                                        self.print_log(log)
                                        clientSock.close()
                                        done = True
                                        break
                                    else:
                                        log = f'no response from {clientAddr}: closing connection'
                                        server_log(userArray[userID], log)                             
                                        self.print_log(log)
                                        clientSock.close()
                                        done = True
                                        break                  
                    # downloading directory
                    elif transferType == cOP.directory:
                        # receiving directory name
                        clientSock.send(cOP.OK.encode())
                        dirName = clientSock.recv(1024)
                        dirName = self.decrypt_data(dirName)
                        dirName = dirName.decode()                       
                        # check if directory does exist
                        log = f'searching requested directory for {clientAddr}'
                        server_log(userArray[userID], log)                             
                        self.print_log(log)
                        for dirpath, dirnames, files in os.walk(userArray[userID], topdown=False):
                            for dir_name in dirnames:
                                if dir_name == dirName:
                                    # directory found
                                    dirpath = dirpath + '/'
                                    log = f'directory {dirpath + dir_name} found. sending to client {clientAddr}'
                                    server_log(userArray[userID], log)                             
                                    self.print_log(log)
                                    clientSock.send(cOP.OK.encode())
                                    time.sleep(self.time_delay)                                  
                                    # sending download size
                                    backupSize = self.get_size(dirpath + dir_name)
                                    backupSize = str(backupSize).encode()
                                    backupSize = self.encrypt_data(backupSize)
                                    clientSock.send(backupSize)
                                    time.sleep(self.time_delay)                                 
                                    # sending directory
                                    for dirpath, dirnames, filenames in os.walk(dirpath + dir_name, topdown=False):
                                        # sending transfer ongoing
                                        log = f"sending transferStatus to {clientAddr}"
                                        server_log(userArray[userID], log)                             
                                        self.print_log(log)
                                        clientSock.send(cOP.transfer.encode())
                                        time.sleep(self.time_delay)
                                        dirpath = dirpath + '/'
                                        vPath = self.client1
                                        lenPath = len(vPath)
                                        dirpathSend = dirpath[lenPath:]                                    
                                        # sending directory name
                                        log = f'sending directory name to {clientAddr}'
                                        server_log(userArray[userID], log)                             
                                        self.print_log(log)
                                        dirpathEncr = dirpathSend.encode()
                                        dirpathEncr = self.encrypt_data(dirpathEncr)
                                        clientSock.send(dirpathEncr)
                                        time.sleep(self.time_delay)                                       
                                        # sending files
                                        for file_name in filenames:
                                            log = f'file {file_name} found. sending to client {clientAddr}'
                                            server_log(userArray[userID], log)                             
                                            self.print_log(log)
                                            clientSock.send(cOP.file.encode())
                                            time.sleep(self.time_delay)                                          
                                            # sending file
                                            log = f'sending filename to {clientAddr}'
                                            server_log(userArray[userID], log)                             
                                            self.print_log(log)
                                            file_name_encr = file_name.encode()
                                            file_name_encr = self.encrypt_data(file_name_encr)
                                            clientSock.send(file_name_encr)
                                            time.sleep(self.time_delay)                     
                                            filePath = dirpath+ "/" + file_name
                                            with open(filePath, 'rb') as clientFile:
                                                data = clientFile.read()
                                            clientFile.close()
                                            data = self.encrypt_data(data)
                                            log = f'sending filesize to {clientAddr}'
                                            server_log(userArray[userID], log)                             
                                            self.print_log(log)
                                            fileSize = len(data)
                                            fileSize = str(fileSize).encode()
                                            fileSize = self.encrypt_data(fileSize)
                                            clientSock.send(fileSize)
                                            time.sleep(self.time_delay)
                                            log = f'recieving status from {clientAddr}'
                                            server_log(userArray[userID], log)                             
                                            self.print_log(log)
                                            status = clientSock.recv(1024).decode()
                                            if status == cOP.OK:
                                                log = f'sending bytes to {clientAddr}'
                                                server_log(userArray[userID], log)                             
                                                self.print_log(log)
                                                clientSock.send(data)
                                            else:
                                                log = f'could not resolve status from {clientAddr}'
                                                server_log(userArray[userID], log)                             
                                                self.print_log(log)
                                            log = f'waiting for response from {clientAddr}'
                                            server_log(userArray[userID], log)                             
                                            self.print_log(log)
                                            resp = clientSock.recv(1024).decode()
                                            if resp == cOP.OK:
                                                log = f'OK recieved from {clientAddr}'
                                                server_log(userArray[userID], log)                             
                                                self.print_log(log)
                                                pass
                                            else:
                                                log = f'no response from {clientAddr}: closing connection'
                                                server_log(userArray[userID], log)                             
                                                self.print_log(log)
                                                clientSock.close()
                                                break                                  
                                    # request completed
                                    f'operation completed for client {clientAddr}'
                                    server_log(userArray[userID], log)                             
                                    self.print_log(log)
                                    done = True
                                    clientSock.send(cOP.rst.encode())
                                    break                  
                    # wrong operand choosen from client
                    else:
                        clientSock.send(cOP.rst.encode())
                        log = f'wrong operand from {clientAddr}'
                        write_log(log)
                        clientSock.close()                      
                    if done:
                        pass
                    else:
                        f'closing connection to {clientAddr}: could not locate file or directory'
                        server_log(userArray[userID], log)                             
                        self.print_log(log)
                        clientSock.send(cOP.rst.encode())
                        clientSock.close()           
            # list filesystem request
            elif data == cOP.listfs:
                listfs = ''
                grep = ''             
                # user identification --> necessary for client system path                
                userID = self.user_config(clientSock, clientAddr)
                if userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.rst.encode())
                    clientSock.close()
                else:
                    clientSock.send(cOP.OK.encode())
                    outputType = clientSock.recv(1024).decode()
                    cut = len(userArray[userID])                  
                    # sending client file system 
                    for dirpath, dirnames, files in os.walk(userArray[userID], topdown=False):
                        listfs = listfs + (f' Directory: {dirpath[cut-1:]} \r\n')
                        grep = grep + (f'Directory: {dirpath[cut-1:]} \r\n')
                        for file_name in files:
                            listfs = listfs + (f'    \'----------> {file_name}\r\n')
                            grep = grep + (f'File: {dirpath[cut-1:]}/{file_name} \r\n')
                    log = f'sending filesystem to {clientAddr}'
                    server_log(userArray[userID], log)                                                 
                    self.print_log(log)
                    time.sleep(self.time_delay)                 
                    # custom output
                    if outputType == cOP.listfs:
                        listfs = listfs.encode()
                        listfs = self.encrypt_data(listfs)
                        fileSize = len(listfs)
                        fileSize = str(fileSize).encode()
                        fileSize = self.encrypt_data(fileSize)
                        clientSock.send(fileSize)
                        time.sleep(self.time_delay)
                        clientSock.send(listfs)                
                    # grepable output    
                    elif outputType == cOP.grep:
                        grep = grep.encode()
                        grep = self.encrypt_data(grep)
                        fileSize = len(grep)
                        fileSize = str(fileSize).encode()
                        fileSize = self.encrypt_data(fileSize)
                        clientSock.send(fileSize)
                        time.sleep(self.time_delay)
                        clientSock.send(grep)                     
                    # wrong operand choosen by client
                    else:
                        log = f'recieved wrong operand'
                        server_log(userArray[userID], log)                                                 
                        self.print_log(log)
                        write_log(f'recieved wrong listfs operand from {clientAddr}')
                        clientSock.send(cOP.rst.encode())
                        clientSock.close()
                    # finish request
                    log = f'waiting for OK from {clientAddr}'
                    server_log(userArray[userID], log)                                                 
                    self.print_log(log)
                    recv = clientSock.recv(1024)
                    if recv.decode() == cOP.OK :
                        log = f'OK recieved. closing connection to {clientAddr}'
                        server_log(userArray[userID], log)                                                 
                        self.print_log(log)
                        clientSock.close()                     
            # remove data request
            elif data == cOP.remove:
                # user identification --> necessary for client system path                
                userID = self.user_config(clientSock, clientAddr)
                if userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.rst.encode())
                    clientSock.close()
                else:
                    clientSock.send(cOP.OK.encode())                 
                    # receiving name
                    removeName = clientSock.recv(1024)
                    removeName = self.decrypt_data(removeName)
                    removeName = removeName.decode()                 
                    # remove file or directory if existing
                    if os.path.exists(userArray[userID] + removeName):
                        try:
                            os.remove(userArray[userID] + removeName)
                        except OSError:
                            shutil.rmtree(userArray[userID] + removeName)
                        log = f'removed {userArray[userID] + removeName}'
                        server_log(userArray[userID], log)                                                 
                        self.print_log(log)
                        clientSock.send(cOP.OK.encode())
                        clientSock.close()
                    else:
                        clientSock.send(cOP.notfound.encode())
                        log = f'file_not_found_error: {userArray[userID] + removeName}'
                        server_log(userArray[userID], log)                                                                         
                        self.print_log(log)
                        clientSock.close()
            # ping request
            elif data == cOP.ping:
                clientSock.send(cOP.OK.encode())
                ping = f'sending ping request to {clientAddr}'
                write_log(ping)
                self.print_log(ping)
                self.print_log(f'closed connection to {clientAddr}')
                clientSock.close()          
            # reset
            elif data == cOP.rst:
                pass          
            # client update request
            elif data == cOP.serverupdate:
                with open(self.client1 + 'ultron-server/uc', 'r') as file:
                    data = file.read()
                file.close()
                data = data.encode()
                data = self.encrypt_data(data)                
                fileSize = len(data)
                fileSize = str(fileSize).encode()
                fileSize = self.encrypt_data(fileSize)
                clientSock.send(fileSize)
                time.sleep(self.time_delay)
                clientSock.send(data)
                updatedb = f'sending update to {clientAddr}: closing connection'
                write_log(updatedb)
                self.print_log(updatedb)
                clientSock.close()           
            # file system decryption request
            elif data == cOP.decrypt:
                key = clientSock.recv(1024)
                key = self.decrypt_data(key)
                key = key.decode()
                try:
                    os.system(f'crypt -d -ks {key} -r {self.client1}')
                    clientSock.send("[*] decryption completed")
                except Exception as e:
                    print(e)
                    write_log(e)
                    clientSock.send("[-] decryption failed! output: ", e)          
            # file system encryption request
            elif data == cOP.encrypt:
                key = clientSock.recv(1024)
                key = self.decrypt_data(key)
                key = key.decode()
                try:
                    os.system(f"crypt -e -ks {key} -r {self.client1}")
                    clientSock.send("[*] encryption completed")
                except Exception as e:
                    print(e)
                    write_log(e)
                    clientSock.send("[-] encryption failed! output: ", e)             
            # file upload request    
            elif data == cOP.upload:
                # user identification --> necessary for client system path                
                userID = self.user_config(clientSock, clientAddr)
                if userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.forbidden.encode())
                    clientSock.close()
                else:
                    clientSock.send(cOP.OK.encode())               
                    # receiving file data
                    log = f'recieving file from {clientAddr}'
                    server_log(userArray[userID], log)                                                                         
                    self.print_log(log)
                    fragmentCount = 0
                    fileDir = clientSock.recv(1024)
                    fileDir = self.decrypt_data(fileDir)
                    fileDir = fileDir.decode()
                    checkDir = self.fetch_dir(fileDir)
                    if checkDir == 'not available':
                        pass
                    else:
                        self.check_dir(userArray[userID] + checkDir)
                    log = f'recieved filedirectory from {clientAddr}'
                    server_log(userArray[userID], log)                                                                                             
                    self.print_log(log)
                    fileData = ''
                    time.sleep(self.time_delay)
                    filesize = clientSock.recv(1024)
                    filesize = self.decrypt_data(filesize)
                    filesize = filesize.decode()
                    filesize = int(filesize)
                    log = f'recieved filesize from {clientAddr}'
                    server_log(userArray[userID], log)                                                                         
                    self.print_log(log)
                    recieved = False
                    if filesize > 1448:
                        fragmentCount = filesize / 1448
                        fragmentCount += 2
                    else:
                        fragmentCount = 1
                    for i in range(int(fragmentCount)):
                        fileBytes = clientSock.recv(1500)
                        fileBytes = fileBytes.decode()
                        fileData += fileBytes
                        log = f'recieving bytes: {len(fileData)}/{filesize}'
                        server_log(userArray[userID], log)                                                                         
                        self.print_log(log)
                        if filesize == len(fileData):
                            log = f'recieved bytes successfully from {clientAddr}'
                            server_log(userArray[userID], log)                                                                         
                            self.print_log(log)
                            recieved = True
                            break
                    fileData = fileData.encode()
                    fileData = self.decrypt_data(fileData)
                    filePath = userArray[userID] + fileDir
                    with open(filePath, 'wb') as openFile:
                        openFile.write(fileData)
                    openFile.close()
                    if recieved:
                        log = f'file from {clientAddr} written to  {filePath}'
                        server_log(userArray[userID], log)                                                                         
                        self.print_log(log)
                        clientSock.send(cOP.OK.encode())
                        clientSock.close()
                    else:
                        log = f'filesize comparison went wrong. ERROR in {filesize}=={os.path.getsize(filePath)}. closing connection to {clientAddr}'
                        server_log(userArray[userID], log)                                                                         
                        self.print_log(log)
                        clientSock.send(cOP.rst.encode())
                        clientSock.close()
            # token authentificaion request
            elif data == cOP.usertoken:
                if self.authtoken_check(clientSock, clientAddr):
                    clientSock.send(cOP.OK.encode())
                    log = f'closing connection to {clientAddr}: job done'
                    server_log(userArray[userID], log)                                                                         
                    self.print_log(log)
                    clientSock.close()
                else:
                    clientSock.send(cOP.rst.encode())
                    error = f'closing connection to {clientAddr}: token invalid'
                    write_log(error)
                    self.print_log(error)
                    clientSock.close()           
            ## ultron package installer 
            # package request
            elif data == cOP.package:
                # user identification --> necessary for client system path                
                userID = self.user_config(clientSock, clientAddr)
                if userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.forbidden.encode())
                    clientSock.close()
                else:                
                    clientSock.send(cOP.OK.encode())                  
                    # receiving package name
                    package = clientSock.recv(1024)
                    package = self.decrypt_data(package)
                    package = package.decode()
                    package_folder = userArray[userID] + '/ultron-server/packages/' + package
                    log = f'searching requested package {package_folder} for {clientAddr}'
                    server_log(userArray[userID], log)                                                                         
                    self.print_log(log)
                    done = False                 
                    # send package if existing
                    if os.path.exists(package_folder):
                        log = f'package {package_folder} found. sending to client {clientAddr}'
                        server_log(userArray[userID], log)                                                                         
                        self.print_log(log)
                        clientSock.send(cOP.OK.encode())
                        time.sleep(self.time_delay)
                        backupSize = self.get_size(package_folder)
                        backupSize = str(backupSize).encode()
                        backupSize = self.encrypt_data(backupSize)
                        clientSock.send(backupSize)
                        time.sleep(self.time_delay)                   
                        for dirpath, dirnames, filenames in os.walk(package_folder, topdown=False):
                            log = f"sending transferStatus to {clientAddr}"
                            server_log(userArray[userID], log)                                                                         
                            self.print_log(log)
                            clientSock.send(cOP.transfer.encode())
                            time.sleep(self.time_delay)
                            dirpath = dirpath + '/'
                            vPath = self.client1
                            lenPath = len(vPath)
                            dirpathSend = dirpath[lenPath:]
                            log = f'sending directory name to {clientAddr}'
                            server_log(userArray[userID], log)                                                                                                     
                            self.print_log(log)
                            dirpathEncr = dirpathSend.encode()
                            dirpathEncr = self.encrypt_data(dirpathEncr)
                            clientSock.send(dirpathEncr)
                            time.sleep(self.time_delay)                        
                            for file_name in filenames:
                                log = f'file {file_name} found. sending to client {clientAddr}'
                                server_log(userArray[userID], log)                                                                         
                                self.print_log(log)
                                clientSock.send(cOP.file.encode())
                                time.sleep(self.time_delay)
                                log = f'sending filename to {clientAddr}'
                                server_log(userArray[userID], log)                                                                         
                                self.print_log(log)
                                file_name_encr = file_name.encode()
                                file_name_encr = self.encrypt_data(file_name_encr)
                                clientSock.send(file_name_encr)
                                time.sleep(self.time_delay)
                                filePath = dirpath+ "/" + file_name                             
                                with open(filePath, 'rb') as clientFile:
                                    data = clientFile.read()
                                clientFile.close()                         
                                data = self.encrypt_data(data)
                                log = f'sending filesize to {clientAddr}'
                                server_log(userArray[userID], log)                                                                         
                                self.print_log(log)
                                fileSize = len(data)
                                fileSize = str(fileSize).encode()
                                fileSize = self.encrypt_data(fileSize)
                                clientSock.send(fileSize)
                                time.sleep(self.time_delay)
                                log = f'recieving status from {clientAddr}'
                                server_log(userArray[userID], log)                                                                         
                                self.print_log(log)
                                status = clientSock.recv(1024).decode()                              
                                if status == cOP.OK:
                                    log = f'sending bytes to {clientAddr}'
                                    server_log(userArray[userID], log)                                                                         
                                    self.print_log(log)
                                    clientSock.send(data)
                                else:
                                    log = f'could not resolve status from {clientAddr}'
                                    server_log(userArray[userID], log)                                                                         
                                    self.print_log(log)                             
                                self.print_log(f'waiting for response from {clientAddr}')
                                resp = clientSock.recv(1024).decode()                             
                                if resp == cOP.OK:
                                    log = f'OK recieved from {clientAddr}'
                                    server_log(userArray[userID], log)                                                                         
                                    self.print_log(log)
                                    pass
                                else:
                                    log = f'no response from {clientAddr}: closing connection'
                                    server_log(userArray[userID], log)                                                                         
                                    self.print_log(log)
                                    clientSock.close()
                                    break  
                        log = f'operation completed for client {clientAddr}'
                        server_log(userArray[userID], log)                                                                         
                        self.print_log(log)
                        done = True
                        clientSock.send(cOP.rst.encode())                 
                    else:
                        log = f'closing connection to {clientAddr}: could not locate package'
                        server_log(userArray[userID], log)                                                                         
                        self.print_log(log)
                        clientSock.send(cOP.rst.encode())
                        clientSock.close()                                  
            # list all packages request
            elif data == cOP.listall:
                # user identification --> necessary for client system path                
                userID = self.user_config(clientSock, clientAddr)
                if userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.forbidden.encode())
                    clientSock.close()
                else:
                    # sending package list
                    clientSock.send(cOP.OK.encode())
                    packageList = []
                    versionList = []
                    output = "Available packages:\r\n"                  
                    for dirpath, dirnames, dirfiles in os.walk(userArray[userID] + '/ultron-server/packages/'):
                        for name in dirnames:
                            packageList.append(name)
                        for filename in dirfiles:
                            if filename == "version.md":
                                with open (dirpath + "/" + filename, 'r') as f:
                                    fileData = f.read()
                                f.close()
                                versionList.append(fileData)
                            else:
                                pass                                 
                    for x in range(len(packageList)):
                        output += f"""---------------------------------
package: {packageList[x]}
version: {versionList[x]}"""                   
                    output = output + 33 * '-'  + "\r\ntotal packages: " + str(len(packageList))
                    log = f'sending list to {clientAddr}'
                    server_log(userArray[userID], log)                                                                         
                    self.print_log(log)
                    output = output.encode()
                    output = self.encrypt_data(output)
                    time.sleep(self.time_delay)
                    clientSock.send(output)              
            # checks if package is available        
            elif data == cOP.search:
                # user identification --> necessary for client system path                
                userID = self.user_config(clientSock, clientAddr)
                if userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.forbidden.encode())
                    clientSock.close()
                else:
                    # sends package information if available
                    clientSock.send(cOP.OK.encode())
                    data = clientSock.recv(1024)
                    data = self.decrypt_data(data)
                    package = data.decode()
                    version = ''
                    packageAvailable = False
                    for dirpath, dirnames, dirfiles in os.walk(userArray[userID] + '/ultron-server/packages/'):
                        for filename in dirfiles:
                            if filename == package:
                                packageAvailable = True
                                with open (dirpath + "/version.md", 'r') as f:
                                    version = f.read()
                                f.close()
                                info = f"""Package found!
name: {package}
version: {version}"""
                                info = self.encrypt_data(info.encode())
                                clientSock.send(info)
                                clientSock.close()
                            else:
                                pass             
                if packageAvailable:
                    pass              
                else:
                    info = f"Package {package} not found."
                    info = self.encrypt_data(info.encode())
                    clientSock.send(info)
                    clientSock.close()         
            else:
                clientSock.send(cOP.rst.encode())
                self.print_log(f'closed connection to {clientAddr}: wrong operand: {data}')
                write_log(f'closed connection to {clientAddr}: wrong operand: {data}')
                clientSock.close()
            
            
    # Denial of Service protection
    def ddos_protection(self, current_date_time, clientAddr):
        # checks if protection already active
        if self.ddos_protection_active:
            pass
        else:
            # DDoS protection indicates a new thread which counts incoming connections
            # if the number of connections does exceed max_conn_number_ddos within 10 seconds the server
            # initializes shutdown and contacts the admin per mail about a potential DDoS attack          
            self.ddos_protection_active = True
            ddos = "[*] DDoS protection " + colors.GREEN + "enabled" + colors.WHITE
            self.print_log(ddos)
            curr_con = self.total_con
            time.sleep(10)
            ddos_con = self.total_con - curr_con 
            if ddos_con > int(self.max_conn_number_ddos):
                self.shutdown_server()
                log = colors.RED + "SECURITY ALERT! DDoS Attack detected!" + colors.WHITE
                self.print_log(log)
                log = f"---DDoS information---\r\nTotal connections: {ddos_con}\r\nDatetime: {current_date_time}\r\nIP-Address: {clientAddr}\r\nDelay: 10s"
                write_ddos_log(log)
                self.send_email(self.targetEmail, self.userEmail, self.creditFile, log)
                sys.exit()
            else:
                self.ddos_protection_active = False       
        
    # function to send an E-Mail
    # does only work with outlook mail
    def send_email(self, targetEmail, userEmail, crFile, log):
    
        with open(crFile, 'r') as f:
            password = f.read()
        f.close()
        log = "Connecting to outlook-server ..."
        server_main_log(log)
        print(log, end="\r")
        try:
            server = smtplib.SMTP('smtp-mail.outlook.com', 587)
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(str(userEmail), str(password))
        except Exception as e:
            log = colors.RED + "ERROR: " + e + colors.WHITE
            print(log)
            server_main_log(log)
            log = "\r\nConnecting to outlook-server [" + colors.RED + "failed" + colors.WHITE + "]\r\n"
            server_main_log(log)
            print(log)
            pass
        log = "Connecting to outlook-server [" + colors.GREEN, "done" + colors.WHITE, "]\r\n"
        server_main_log(log)
        print(log)    
        msg = MIMEMultipart()
        msg['From'] = str("ULTRON-SERVER")
        msg['To'] = str(targetEmail)
        msg['Subject'] = str("DDoS-Attack detected! DDoS-log is described in the message.")
        message = log   
        msg.attach(MIMEText(message, 'plain')) 
        text = msg.as_string()
        try:
            server.sendmail(str(userEmail), str(targetEmail), text)
        except Exception as e:
            log = colors.RED + "ERROR: " + e + colors.WHITE
            server_main_log(log)
            print(log)
            server.quit()
        except KeyboardInterrupt():
            server.quit()
            sys.exit("^C")
        print("Email sent [", colors.GREEN, "+", colors.WHITE, "]")
        log = "\r\nJob done. Quitting server."
        server_main_log(log)
        print(log)
        server.quit() 

    # initialize server
    def configure_server(self):
        log = 'ultron-server version 1.1.6'
        server_main_log(log)
        self.print_log(log)
        log = 'starting server...'
        server_main_log(log)
        self.print_log(log)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        log = f'server listening on {self.host} :: {self.port}'
        server_main_log(log)
        self.print_log(log)

    # connection handling
    def client_connections(self):
        try:
            self.sock.listen(10)
            while True:
                self.total_con += 1
                clientSock, clientAddr = self.sock.accept()
                log = f'recieved request from {clientAddr}'
                server_main_log(log)
                self.print_log(log)
                current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log = f'[{current_date_time}] recv conn from: {clientAddr}'
                server_main_log(log)
                write_logcon(log)
                ddosThread = threading.Thread(target=self.ddos_protection,
                                              args= (current_date_time, clientAddr))
                ddosThread.start()
                clientThread = threading.Thread(target=self.handle_client,
                                                     args = (clientSock, clientAddr))
                clientThread.start()
        except KeyboardInterrupt:
            self.shutdown_server()
        except Exception as error:
            self.print_log(error)
            write_log(error)
            sys.exit()

    # handle client request
    def handle_client(self, clientSock, clientAddr):
        try:
            log = f'waiting for request from {clientAddr}'
            server_main_log(log)
            self.print_log(log)
            option = clientSock.recv(1024)
            log = f'request recieved from {clientAddr}'
            server_main_log(log)
            self.print_log(log)
            self.handling_options(clientSock, clientAddr, option)
        except KeyboardInterrupt:
            sys.exit("^C")
        except Exception as error:
            print(error)
            write_log(error)

    # start server
    def start_server(self):
        try:
            self.client_connections()
        except KeyboardInterrupt:
            self.shutdown_server()
        except Exception as error:
            self.print_log(error)
            write_log(error)
            sys.exit()

    # initialize shut down of server
    def shutdown_server(self):
        log = colors.YELLOW + "WARNING! Server will be shut down soon." + colors.WHITE
        server_main_log(log)
        self.print_log(log)
        self.sock.close()


# main function
def ultron_server():
    # fetching arguments
    if len(sys.argv) == 5 or sys.argv[1] == '--updatedb':
        if sys.argv[1] == "--a":
            host = sys.argv[2]
        elif sys.argv[1] == "--updatedb":
            try:
                os.system("uc --u /ultron-server/us.py us")
                os.system("uc --u /ultron-server/server.cfg server.cfg")
            except Exception as error:
                print(colors.RED, error, colors.WHITE)
            print("updated succesfully")
            sys.exit()
        if sys.argv[3] == "--p":
            port = sys.argv[4]
        else:
            print('version 1.1.6\r\nusage: us --a [ADDRESS] --p [PORT]')
            sys.exit()
    else:
        print('version 1.1.6\r\nusage: us --a [ADDRESS] --p [PORT]')
        sys.exit()
    # creating server object and starting ultron server
    server = TCPServer(host, int(port))
    server.configure_server()
    server.start_server()


# run ultron server
try:
    ultron_server()
except Exception as e:
    error = colors.RED + f'SERVER_ERROR: {e}' + colors.WHITE
    write_log(str(error))
    server_main_log(str(error))
    sys.exit(error)




