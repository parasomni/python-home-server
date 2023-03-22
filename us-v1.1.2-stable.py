#!/usr/bin/python3
# server script 2
# version 1.1.2

# upcomming improvements
# file checker » if file is already downloaded only new files will be downloaded
# directory encryption by user » data is stored encrypted

import socket
import shutil
import sys
import random
import threading
import hashlib
import os
import time

import numpy as np

from os import scandir
from datetime import datetime
from cryptography.fernet import Fernet
from http import client


class colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'

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

def write_log(log):
    current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log = f'[{current_date_time}] {log}'
    with open('err_log.txt', 'a') as errFile:
        errFile.write(str(log) + '\r\n')
    errFile.close()

def write_logcon(log):
    with open('conn_log.txt', 'a') as logFile:
        logFile.write(str(log) + '\r\n')
    logFile.close()

def get_module():
    try:
        import cryptor
        return True
    except:
        return False

class TCPServer:

    def __init__(self, host, port):
        with open('/etc/ultron-server/server.cfg') as configFile:
            ultronConfig = configFile.read()
        configFile.close()
        comma = ','
        commaPos = []
        for pos, char in enumerate(ultronConfig):
            if (char == comma):
                commaPos.append(pos)
        self.client1 = str(ultronConfig[commaPos[0]+1:commaPos[1]])
        self.client2 = str(ultronConfig[commaPos[2]+1:commaPos[3]])
        self.client3 = str(ultronConfig[commaPos[4]+1:commaPos[5]])
        self.client4 = str(ultronConfig[commaPos[6]+1:commaPos[7]])
        self.keyfile = str(ultronConfig[commaPos[8]+1:commaPos[9]])
        self.validtoken = str(ultronConfig[commaPos[10]+1:commaPos[11]])        
        self.host = host
        self.port = port
        self.crypt = get_module()

    def print_log(self, msg):
        current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f'[{current_date_time}] {msg}')

    def encrypt_data(self, fileData):
        with open(self.keyfile, 'rb') as keyFile:
            key = keyFile.read()
        keyFile.close()
        fernet = Fernet(key)
        encryptedData = fernet.encrypt(fileData)
        return encryptedData

    def decrypt_data(self, fileData):
        with open(self.keyfile, 'rb') as keyFile:
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

    def user_config(self, clientSock, clientAddr):
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
            # debuginfo
            # print(valid_token[i], "==", clientToken)
            if valid_token[i] == clientToken:
                self.print_log(f'token is valid from {clientAddr}')
                return i
            elif i > num_token:
                i = ''
                return i

    def check_dir(self, dirPath):
        if os.path.exists(str(dirPath)):
            self.print_log(f'Directory {dirPath} exists.')
            pass
        else:
            self.print_log(f'Directory {dirPath} not exists --> creating...')
            os.makedirs(dirPath)
    
    def get_size(self, dir1):
                total_size = 0
                for dirpath, dirnames, filenames in os.walk(dir1):
                    for f in filenames:
                        fp = os.path.join(dirpath, f)
                        # skip if it is symbolic link
                        if not os.path.islink(fp):
                            total_size += os.path.getsize(fp)
                return total_size

    def fetch_dir(self, uploadFile):
        #print('fetching directory')
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
            userArray = [self.client1, self.client2, self.client3, self.client4]
            if data == cOP.backup:
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
                    self.print_log(f'preparing backup from {clientAddr}')
                    # recieving destDirectory
                    self.print_log(f'recieving Directory from {clientAddr}')
                    destDir = clientSock.recv(1024)
                    destDir = self.decrypt_data(destDir)
                    destDir = destDir.decode()
                    isDir = False
                    # recieving backupsize
                    self.print_log(f'recieving backup-size from {clientAddr}')
                    backupSize = clientSock.recv(2048)
                    backupSize = self.decrypt_data(backupSize)
                    backupSize = backupSize.decode()
                    self.print_log(f'recieving directory name from {clientAddr}')
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
                            else:
                                self.print_log(req)

                        elif status == cOP.file:
                            self.handle_file(clientSock, clientAddr, userArray[userID] + destDir + dirName)

                        elif status == cOP.OK:
                            userDir = userArray[userID] + destDir + dirName
                            currSize = self.get_size(userDir)
                            if currSize == dirSizeBefore:
                                actSize = backupSize
                            else:
                                actSize = currSize - dirSizeBefore
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
                    if transferType == cOP.file:
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
                    elif transferType == cOP.directory:
                        clientSock.send(cOP.OK.encode())
                        dirName = clientSock.recv(1024)
                        dirName = self.decrypt_data(dirName)
                        dirName = dirName.decode()
                        self.print_log(f'searching requested directory for {clientAddr}')
                        for dirpath, dirnames, files in os.walk(userArray[userID], topdown=False):
                            for dir_name in dirnames:
                                if dir_name == dirName:
                                    dirpath = dirpath + '/'
                                    self.print_log(f'directory {dirpath + dir_name} found. sending to client {clientAddr}')
                                    clientSock.send(cOP.OK.encode())
                                    time.sleep(0.3)
                                    #backupSize = self.get_size(userArray[userID] + dir_name)
                                    backupSize = self.get_size(dirpath + dir_name)
                                    backupSize = str(backupSize).encode()
                                    backupSize = self.encrypt_data(backupSize)
                                    clientSock.send(backupSize)
                                    time.sleep(0.3)
                                    for dirpath, dirnames, filenames in os.walk(dirpath + dir_name, topdown=False):
                                        self.print_log(f"sending transferStatus to {clientAddr}")
                                        clientSock.send(cOP.transfer.encode())
                                        time.sleep(0.3)
                                        dirpath = dirpath + '/'
                                        vPath = self.client1
                                        lenPath = len(vPath)
                                        dirpathSend = dirpath[lenPath:]
                                        #dirpathSend = dirpath
                                        self.print_log(f'sending directory name to {clientAddr}')
                                        dirpathEncr = dirpathSend.encode()
                                        dirpathEncr = self.encrypt_data(dirpathEncr)
                                        clientSock.send(dirpathEncr)
                                        time.sleep(0.3)
                                        for file_name in filenames:
                                            self.print_log(f'file {file_name} found. sending to client {clientAddr}')
                                            clientSock.send(cOP.file.encode())
                                            time.sleep(0.3)
                                            #pathName = dirpath + dir_name 
                                            #userLen = len(userArray[userID])
                                            #pathName = pathName[:userLen]
                                            self.print_log(f'sending filename to {clientAddr}')
                                            file_name_encr = file_name.encode()
                                            file_name_encr = self.encrypt_data(file_name_encr)
                                            clientSock.send(file_name_encr)
                                            time.sleep(0.3)
                                            #path_name_encr = pathName.encode()
                                            #path_name_encr = self.encrypt_data(path_name_encr)
                                            #clientSock.send(path_name_encr)
                                            filePath = dirpath+ "/" + file_name
                                            with open(filePath, 'rb') as clientFile:
                                                data = clientFile.read()
                                            clientFile.close()
                                            data = self.encrypt_data(data)
                                            self.print_log(f'sending filesize to {clientAddr}')
                                            fileSize = len(data)
                                            fileSize = str(fileSize).encode()
                                            fileSize = self.encrypt_data(fileSize)
                                            clientSock.send(fileSize)
                                            time.sleep(0.3)
                                            self.print_log(f'recieving status from {clientAddr}')
                                            status = clientSock.recv(1024).decode()
                                            if status == cOP.OK:
                                                self.print_log(f'sending bytes to {clientAddr}')
                                                clientSock.send(data)
                                            else:
                                                self.print_log(f'could not resolve status from {clientAddr}')
                                            self.print_log(f'waiting for response from {clientAddr}')
                                            resp = clientSock.recv(1024).decode()
                                            if resp == cOP.OK:
                                                self.print_log(f'OK recieved from {clientAddr}')
                                                pass
                                            else:
                                                self.print_log(f'no response from {clientAddr}: closing connection')
                                                clientSock.close()
                                                break
                                    self.print_log(f'operation completed for client {clientAddr}')
                                    done = True
                                    clientSock.send(cOP.rst.encode())
                                    break
                    else:
                        clientSock.send(cOP.rst.encode())
                        log = f'wrong operand from {clientAddr}'
                        write_log(log)
                        clientSock.close()
                    if done:
                        pass
                    else:
                        self.print_log(f'closing connection to {clientAddr}: could not locate file or directory')
                        clientSock.send(cOP.rst.encode())
                        clientSock.close()
            elif data == cOP.listfs:
                listfs = ''
                grep = ''
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
                    for dirpath, dirnames, files in os.walk(userArray[userID], topdown=False):
                        listfs = listfs + (f' Directory: {dirpath[cut-1:]} \r\n')
                        grep = grep + (f'Directory: {dirpath[cut-1:]} \r\n')
                        for file_name in files:
                            listfs = listfs + (f'    \'----------> {file_name}\r\n')
                            grep = grep + (f'File: {dirpath[cut-1:]}/{file_name} \r\n')
                    self.print_log(f'sending filesystem to {clientAddr}')
                    time.sleep(0.2)
                    if outputType == cOP.listfs:
                        listfs = listfs.encode()
                        listfs = self.encrypt_data(listfs)
                        fileSize = len(listfs)
                        fileSize = str(fileSize).encode()
                        fileSize = self.encrypt_data(fileSize)
                        clientSock.send(fileSize)
                        time.sleep(0.2)
                        clientSock.send(listfs)
                    elif outputType == cOP.grep:
                        grep = grep.encode()
                        grep = self.encrypt_data(grep)
                        fileSize = len(grep)
                        fileSize = str(fileSize).encode()
                        fileSize = self.encrypt_data(fileSize)
                        clientSock.send(fileSize)
                        time.sleep(0.2)
                        clientSock.send(grep)
                    else:
                        self.print_log(f'recieved wrong operand')
                        write_log(f'recieved wrong listfs operand from {clientAddr}')
                        clientSock.send(cOP.rst.encode())
                        clientSock.close()

                    self.print_log(f'waiting for OK from {clientAddr}')
                    recv = clientSock.recv(1024)
                    if recv.decode() == cOP.OK :
                        self.print_log(f'OK recieved. closing connection to {clientAddr}')
                        clientSock.close()
            elif data == cOP.remove:
                userID = self.user_config(clientSock, clientAddr)
                if userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.rst.encode())
                    clientSock.close()
                else:
                    clientSock.send(cOP.OK.encode())
                    removeName = clientSock.recv(1024)
                    removeName = self.decrypt_data(removeName)
                    removeName = removeName.decode()
                    if os.path.exists(userArray[userID] + removeName):
                        try:
                            os.remove(userArray[userID] + removeName)
                        except OSError:
                            shutil.rmtree(userArray[userID] + removeName)
                        self.print_log(f'removed {userArray[userID] + removeName}')
                        clientSock.send(cOP.OK.encode())
                        clientSock.close()
                    else:
                        clientSock.send(cOP.notfound.encode())
                        self.print_log(f'file_not_found_error: {userArray[userID] + removeName}')
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
                with open(self.client1 + 'ultron-server/uc', 'r') as file:
                    data = file.read()
                file.close()
                data = data.encode()
                data = self.encrypt_data(data)                
                fileSize = len(data)
                fileSize = str(fileSize).encode()
                fileSize = self.encrypt_data(fileSize)
                clientSock.send(fileSize)
                clientSock.send(data)
                updatedb = f'sending update to {clientAddr}: closing connection'
                write_log(updatedb)
                self.print_log(updatedb)
                clientSock.close()
            elif data == cOP.upload:
                userID = self.user_config(clientSock, clientAddr)
                if userID not in (0,1,2,3):
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
                    checkDir = self.fetch_dir(fileDir)
                    if checkDir == 'not available':
                        pass
                    else:
                        self.check_dir(userArray[userID] + checkDir)
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
                        fragmentCount += 2
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
                            break
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
            
            elif data == cOP.package:
                userID = self.user_config(clientSock, clientAddr)
                if userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.forbidden.encode())
                    clientSock.close()
                else:                
                    clientSock.send(cOP.OK.encode())
                    package = clientSock.recv(1024)
                    package = self.decrypt_data(package)
                    package = package.decode()
                    package_folder = userArray[userID] + '/ultron-server/packages/' + package
                    self.print_log(f'searching requested package {package_folder} for {clientAddr}')
                    done = False
                    if os.path.exists(package_folder):
                        self.print_log(f'package {package_folder} found. sending to client {clientAddr}')
                        clientSock.send(cOP.OK.encode())
                        time.sleep(0.3)
                        backupSize = self.get_size(package_folder)
                        backupSize = str(backupSize).encode()
                        backupSize = self.encrypt_data(backupSize)
                        clientSock.send(backupSize)
                        time.sleep(0.3)
                        for dirpath, dirnames, filenames in os.walk(package_folder, topdown=False):
                            self.print_log(f"sending transferStatus to {clientAddr}")
                            clientSock.send(cOP.transfer.encode())
                            time.sleep(0.3)
                            dirpath = dirpath + '/'
                            vPath = self.client1
                            lenPath = len(vPath)
                            dirpathSend = dirpath[lenPath:]
                            #dirpathSend = dirpath
                            self.print_log(f'sending directory name to {clientAddr}')
                            dirpathEncr = dirpathSend.encode()
                            dirpathEncr = self.encrypt_data(dirpathEncr)
                            clientSock.send(dirpathEncr)
                            time.sleep(0.3)
                            for file_name in filenames:
                                self.print_log(f'file {file_name} found. sending to client {clientAddr}')
                                clientSock.send(cOP.file.encode())
                                time.sleep(0.3)
                                #pathName = dirpath + dir_name 
                                #userLen = len(userArray[userID])
                                #pathName = pathName[:userLen]
                                self.print_log(f'sending filename to {clientAddr}')
                                file_name_encr = file_name.encode()
                                file_name_encr = self.encrypt_data(file_name_encr)
                                clientSock.send(file_name_encr)
                                time.sleep(0.3)
                                #path_name_encr = pathName.encode()
                                #path_name_encr = self.encrypt_data(path_name_encr)
                                #clientSock.send(path_name_encr)
                                filePath = dirpath+ "/" + file_name
                                with open(filePath, 'rb') as clientFile:
                                    data = clientFile.read()
                                clientFile.close()
                                data = self.encrypt_data(data)
                                self.print_log(f'sending filesize to {clientAddr}')
                                fileSize = len(data)
                                fileSize = str(fileSize).encode()
                                fileSize = self.encrypt_data(fileSize)
                                clientSock.send(fileSize)
                                time.sleep(0.3)
                                self.print_log(f'recieving status from {clientAddr}')
                                status = clientSock.recv(1024).decode()
                                if status == cOP.OK:
                                    self.print_log(f'sending bytes to {clientAddr}')
                                    clientSock.send(data)
                                else:
                                    self.print_log(f'could not resolve status from {clientAddr}')
                                self.print_log(f'waiting for response from {clientAddr}')
                                resp = clientSock.recv(1024).decode()
                                if resp == cOP.OK:
                                    self.print_log(f'OK recieved from {clientAddr}')
                                    pass
                                else:
                                    self.print_log(f'no response from {clientAddr}: closing connection')
                                    clientSock.close()
                                    break
                        self.print_log(f'operation completed for client {clientAddr}')
                        done = True
                        clientSock.send(cOP.rst.encode())
                    else:
                        self.print_log(f'closing connection to {clientAddr}: could not locate package')
                        clientSock.send(cOP.rst.encode())
                        clientSock.close()                        
            
            elif data == cOP.listall:
                userID = self.user_config(clientSock, clientAddr)
                if userID not in (0,1,2,3):
                    error = f'closing connection to {clientAddr}: invalid auth_token'
                    write_log(error)
                    self.print_log(error)
                    clientSock.send(cOP.forbidden.encode())
                    clientSock.close()
                else:                
                    clientSock.send(cOP.OK.encode())
                    packageList = []
                    versionList = []
                    i = 0
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
                        i+=1
                            
                    for x in range(len(packageList) - 1):
                        output += f"""---------------------------------
package: {packageList[x]}
version: {versionList[x]}"""

                    output = output + 33 * '-'  + "\r\ntotal packages: " + str(len(packageList))
                    self.print_log(f'sending list to {clientAddr}')
                    output = output.encode()
                    output = self.encrypt_data(output)
                    time.sleep(0.3)
                    clientSock.send(output)
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
    if len(sys.argv) == 5 or sys.argv[1] == '--updatedb':
        if sys.argv[1] == "--a":
            host = sys.argv[2]
        elif sys.argv[1] == "--updatedb":
            try:
                os.system("uc --u /ultron-server/us.py us.py")
                os.system("uc --u /ultron-server/server.cfg server.cfg")
            except Exception as error:
                print(colors.RED, error, colors.WHITE)
            print("updated succesfully")
            sys.exit()
        if sys.argv[3] == "--p":
            port = sys.argv[4]
        else:
            print('ultron_server_beta | usage: ./us.py --a [ADDRESS] --p [PORT]')
            sys.exit()
    else:
        print('ultron_server_beta | usage: ./us.py --a [ADDRESS] --p [PORT]')
        sys.exit()

    server = TCPServer(host, int(port))
    server.configure_server()
    server.start_server()



try:
    start_server()
except Exception as e:
    error = colors.RED + f'SERVER_ERROR: {e}' + colors.WHITE
    write_log(str(error))
    sys.exit(error)
