#!/usr/bin/python3
# version 1.1.8

# import required modules
import socket
import subprocess
import shutil
import smtplib
import sys
import threading
import os
import time

from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from http import client
from email import encoders
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart


# checks if directory exists or needs to be created
def check_dir(dirPath):
    if os.path.exists(str(dirPath)):
        pass
    else:
        os.makedirs(dirPath)


# debug class
class Debug:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def debug(self, message):
        if self.enabled:
            debug_message = f"[DEBUG]: {message}"
            print(debug_message)
            self.write_log(debug_message)

    def write_log(self, message):
        current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log = f'[{current_date_time}] {message}'
        current_date_time = datetime.now().strftime('%Y-%m-%d')
        check_dir("/etc/ultron-server/debug")
        path = f"/etc/ultron-server/debug/{current_date_time}.log"
        with open(path, "a") as log_file:
            log_file.write(log + "\n")
        log_file.close()


# encryption stub
class EncryptionStub:
    def __init__(self, debugger):
        self.debugger = debugger

    def generate_ecdh_keys(self):
        self.debugger.debug(f"[{threading.get_ident()}] Generating ecdh keys")
        server_private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend())
        server_public_key = server_private_key.public_key()
        self.debugger.debug(
            f"[{threading.get_ident()}] Generating ecdh keys done")
        return server_public_key, server_private_key

    def generate_key_iv(self):
        key = os.urandom(32)  # Generate a 256-bit (32-byte) key
        iv = os.urandom(16)   # Generate a 128-bit (16-byte) IV
        return key, iv

    def encrypt_data(self, key, iv, plaintext, text=True):
        if text:
            plaintext = plaintext.encode('utf-8')
        self.debugger.debug(f"Plaintext before encryption: {plaintext}")
        cipher = Cipher(
            algorithms.AES(
                key), modes.CBC(
                iv), backend=default_backend())
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        self.debugger.debug(f"Padded plaintext: {padded_plaintext}")
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        self.debugger.debug(f"Ciphertext: {ciphertext}")
        return ciphertext

    def decrypt_data(self, key, iv, ciphertext, text=True):
        self.debugger.debug(f"Ciphertext before decryption: {ciphertext}")
        cipher = Cipher(
            algorithms.AES(
                key), modes.CBC(
                iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        self.debugger.debug(
            f"Padded plaintext after decryption: {padded_plaintext}")
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        self.debugger.debug(f"Plaintext after unpadding: {plaintext}")
        if text:
            return plaintext.decode('utf-8')
        return plaintext
    
    def setup_encryption(self, conn):
        self.debugger.debug(
            f"[{threading.get_ident()}] Start of encryption setup")
        self.debugger.debug(
            f"[{threading.get_ident()}] Generating server key pair")
        server_public_key, server_private_key = self.generate_ecdh_keys()
        self.debugger.debug(
            f"[{threading.get_ident()}] Serializing key pair to pem format")
        server_public_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.debugger.debug(
            f"[{threading.get_ident()}] Serializing key pair to pem format done")
        self.debugger.debug(
            f"[{threading.get_ident()}] Sending public key bytes to client")
        conn.sendall(server_public_bytes)
        self.debugger.debug(
            f"[{threading.get_ident()}] Receiving client public key bytes")
        client_public_bytes = conn.recv(1024)
        self.debugger.debug(
            f"[{threading.get_ident()}] Serializing client public key bytes to pem format")
        client_public_key = serialization.load_pem_public_key(
            client_public_bytes,
            backend=default_backend()
        )
        self.debugger.debug(
            f"[{threading.get_ident()}] Generating shared secret")
        shared_secret = server_private_key.exchange(
            ec.ECDH(), client_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32 + 16,  # 32 bytes for AES-256 key, 16 bytes for IV
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)
        key = derived_key[:32]
        iv = derived_key[32:48]
        self.debugger.debug(
            f"[{threading.get_ident()}] End of encryption setup")
        return key, iv



# class for colored output
class colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'


# necessary oparands for communication between client and server
class cOP:
    FILE = "334"
    DIR = "336"
    TRANSFER = "340"
    OK = "200"
    FORBIDDEN = "403"
    NOT_FOUND = "404"
    UPLOAD = "300"
    REMOVE = "299"
    DOWNLOAD = "301"
    SERVERUPDATE = "302"
    PING = "303"
    BACKUP = "304"
    LISTFS = "306"
    GREP = "307"
    USERTOKEN = "100"
    RST = "RST"
    PACKAGE = "310"
    LISTALL = "311"
    ENCRYPT = "000"
    DECRYPT = "999"
    SEARCH = "876"
    LOCK = "503"


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

def write_crypt_key(key):
    with open('password.txt', 'w') as keyFile:
        keyFile.write(key)
    keyFile.close()

def write_crypt_dir(dir):
    with open('directory.txt', 'w') as dirFile:
        dirFile.write(dir)
    dirFile.close()

# log client actions
def server_log(client, log):
    date = datetime.now().strftime('%Y%m%d')
    client_server_path = '/etc/ultron-server/' + client.split('/')[-1]
    check_dir(client_server_path)
    with open(client_server_path + '/' + date + '.txt', 'a') as log_file:
        log_file.write(str(log) + '\r\n')
    log_file.close()

# server main log
def server_main_log(log):
    server_main_log_path = '/etc/ultron-server/main-logs/'
    date = datetime.now().strftime('%Y%m%d')
    current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log = f'[{current_date_time}] {log}'
    check_dir(server_main_log_path)
    with open(server_main_log_path + date + '.txt', 'a') as log_file:
        log_file.write(str(log) + '\r\n')
    log_file.close()


server_version = 'v1.1.8'

# mutex
server_main_log_lock = threading.Lock()
server_log_lock = threading.Lock()
write_log_lock = threading.Lock()
write_log_conn_lock = threading.Lock()
backup_client1_lock = threading.Lock()


# server implementation
class TCPServer:
    # initialize server
    def __init__(self, host, port, debugger):
        # load configuration
        with open('/etc/ultron-server/server.cfg') as configFile:
            ultronConfig = configFile.read()
        configFile.close()
        comma = ','
        commaPos = []
        for pos, char in enumerate(ultronConfig):
            if (char == comma):
                commaPos.append(pos)

        self.debugger = debugger
        self.crypt_stub = EncryptionStub(debugger)
        self.crypt_clients_list = {}

        # set configuration
        self.client1 = str(ultronConfig[commaPos[0] + 1:commaPos[1]])
        self.client2 = str(ultronConfig[commaPos[2] + 1:commaPos[3]])
        self.client3 = str(ultronConfig[commaPos[4] + 1:commaPos[5]])
        self.client4 = str(ultronConfig[commaPos[6] + 1:commaPos[7]])
        self.keyfile = str(ultronConfig[commaPos[8] + 1:commaPos[9]])
        self.validtoken = str(ultronConfig[commaPos[10] + 1:commaPos[11]])
        self.time_delay = float(ultronConfig[commaPos[12] + 1:commaPos[13]])
        self.max_conn_number_ddos = int(
            ultronConfig[commaPos[14] + 1:commaPos[15]])
        self.userEmail = str(ultronConfig[commaPos[16] + 1:commaPos[17]])
        self.targetEmail = str(ultronConfig[commaPos[18] + 1:commaPos[19]])
        self.creditFile = str(ultronConfig[commaPos[20] + 1:commaPos[21]])
        self.host = host
        self.port = port
        self.total_con = 0
        self.ddos_protection_active = False
        self.key = 0
        self.iv = 0


    # print log to stdout
    def print_log(self, msg):
        current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f'[{current_date_time}] {msg}')

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

    def check_dir_sec(self, dir):
        if '..' in dir:
            return False
        else:
            return True

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

    def end_check(self, dirSizeBefore, backupSize, destDir):
        currSize = self.get_size(destDir)
        if currSize == dirSizeBefore:
            actSize = backupSize
        else:
            actSize = currSize - dirSizeBefore
        if int(backupSize) == int(actSize):
            return True
        else:
            return False

    # check if tokens are equal
    def token_check(self, recvToken, token):
        if recvToken == token:
            return True
        else:
            return False

    # verification of authentification token
    def authtoken_check(self, clientSock, clientAddr):
        clientToken = clientSock.recv(1024)
        clientToken = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], clientToken)
        clientToken = clientToken[0:30]
        self.print_log(f'fetching token from db for {clientAddr}')
        with open(self.validtoken, "r") as vtFile:
            tokens = vtFile.read()
        vtFile.close()
        count = len(tokens)
        num = count / 30
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

                server_main_log(
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} token {clientToken} invalid from {clientAddr}")
                server_main_lock.release()
                return True
            elif i > num_token:
                return False

    # identifies authenticated user
    def user_config(self, clientSock, clientAddr):
        # token verification
        clientToken = clientSock.recv(1024)
        clientToken = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], clientToken)
        clientToken = clientToken[0:30]
        self.print_log(f'fetching token from db for {clientAddr}')
        with open(self.validtoken, "r") as vtFile:
            tokens = vtFile.read()
        vtFile.close()
        count = len(tokens)
        num = count / 30
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
        slashCount = len(slashPos) - 1
        if slashCount >= 1:
            slashPosx = slashPos[slashCount]
            fileDir = uploadFile[0:slashPosx]
        else:
            fileDir = 'not available'
        return fileDir

    # file handling
    def handle_file(self, clientSock, clientAddr, fileDirectory):
        self.debugger.debug(
            f"[{threading.get_ident()}] Start of file transfer")
        clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
        self.print_log(f'receiving file-info from {clientAddr}')

        # receiving fileName
        fileName = clientSock.recv(1024)
        fileName = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], fileName)
        fileFormat = fileName[-4:]
        self.print_log(f'received fileName {fileName} from {clientAddr}')
        # receiving fileSize
        fileSize = clientSock.recv(1024)
        fileSize = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], fileSize)

        self.print_log(f'received fileSize {fileSize} from {clientAddr}')
        # receiving fileBytesSize
        fileBytesSize = clientSock.recv(1024)
        fileBytesSize = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], fileBytesSize)
        self.print_log(
            f'recieved fileBytesSize {fileBytesSize} from {clientAddr}')
        # receiving bytes from file
        self.print_log(f'receiving fileBytes from {clientAddr}')
        fragmentCount = 0
        fileData = b''
        fileBytesSize = int(fileBytesSize)
        while True:
            self.print_log(f'receiving fileBytes from {clientAddr}')
            fileBytes = clientSock.recv(1024)
            fileData += fileBytes
            self.print_log(f'received bytes: {len(fileData)}/{fileSize}')
            if int(fileBytesSize) == int(len(fileData)):
                self.print_log(
                    f'fileBytes recieved successfully from {clientAddr}')
                break
            else:
                self.print_log(f'fileBytes missing from {clientAddr}')
                pass
        # decrypting and decoding data
        self.print_log(f'decrypting and decoding bytes from {clientAddr}')
        fileData = fileData
        fileData = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], fileData, False)
        specFileFormat = False
        time.sleep(self.time_delay)
        # writing file
        if not specFileFormat:
            self.print_log(
                f'file received from {clientAddr} with {
                    len(fileData)} bytes. writing to directory')
            with open(fileDirectory + fileName, 'wb') as openFile:
                openFile.write(fileData)
            openFile.close()
            self.print_log(
                f'file from {clientAddr} written to {
                    fileDirectory + fileName}')
        fileSize = int(fileSize)
        self.print_log(f'comparing fileSize {fileSize} == {len(fileData)}')
        # sending finish and closing socket
        if fileSize == len(fileData):
            self.print_log(f'filesize OK. sending answer to {clientAddr}')
            clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
        else:
            message = 'server_side_error occurred. please try upload again.'
            error = f'fileSize comparing failed. sending answer to {clientAddr}'
            write_log(error)
            self.print_log(error)
            clientSock.send(message)
            clientSock.close()
            del self.crypt_clients_list[threading.get_ident()]
        self.debugger.debug(f"[{threading.get_ident()}] End of file transfer")

    def send_package():
        pass

    # main function of request handling
    def handling_options(self, clientSock, clientAddr, data):
        # decoding request
        userArray = [
            self.client1,
            self.client2,
            self.client3,
            self.client4]
        # backup request
        if data == cOP.BACKUP:
            # user identification --> necessary for client system path
            userID = self.user_config(clientSock, clientAddr)
            fileTransfer = True
            global isDir
            if userID not in (0, 1, 2, 3):
                error = f'closing connection to {clientAddr}: invalid auth_token'
                write_log(error)
                self.print_log(error)
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.FORBIDDEN))
                clientSock.close()
                del self.crypt_clients_list[threading.get_ident()]
            else:
                self.debugger.debug(
                    f"[{threading.get_ident()}] Trying to acquire lock")
                if backup_client1_lock.acquire(blocking=False):
                    self.debugger.debug(
                        f"[{threading.get_ident()}] Trying to acquire lock done")
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                else:
                    self.debugger.debug(
                        f"[{threading.get_ident()}] Waiting for client lock")
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.LOCK))
                    backup_client1_lock.acquire()
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                try:
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                    log = f'preparing backup from {clientAddr}'
                    server_log(userArray[userID], log)

                    self.print_log(log)
                    # receiving destDirectory
                    log = f'receiving Directory from {clientAddr}'
                    server_log(userArray[userID], log)
                    self.print_log(log)
                    destDir = clientSock.recv(1024)
                    destDir = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], destDir)
                    if not self.check_dir_sec(destDir):
                        log = f"WARNING: Detected potential security threat! {clientAddr}"

                        server_main_log(log)

                        clientSock.close()
                        del self.crypt_clients_list[threading.get_ident()]
                    else:
                        isDir = False
                        # receiving backupsize
                        log = f'receiving backup-size from {clientAddr}'

                        server_log(userArray[userID], log)

                        self.print_log(log)
                        backupSize = clientSock.recv(2048)
                        backupSize = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], backupSize)
                        log = f'receiving directory name from {clientAddr}'

                        server_log(userArray[userID], log)

                        self.print_log(log)
                        # getting dirSizeBefore
                        first_dir_name = clientSock.recv(2048)
                        first_dir_name = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], 
                            first_dir_name)
                        if not self.check_dir_sec(first_dir_name):
                            log = f"WARNING: Detected potential security threat! {clientAddr}"

                            server_main_log(log)

                            clientSock.close()
                            del self.crypt_clients_list[threading.get_ident()]
                        else:
                            self.check_dir(
                                userArray[userID] + destDir)
                            dirSizeBefore = self.get_size(
                                userArray[userID] + destDir + first_dir_name)
                            # receiving backup
                            while fileTransfer:
                                # receiving fileTransfer status
                                if not isDir:
                                    log = f'receiving fileTransferStatus from {clientAddr}'

                                    server_log(
                                        userArray[userID], log)

                                    self.print_log(log)
                                    status = clientSock.recv(16)
                                    status = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], 
                                        status)
                                else:
                                    pass
                                global dirName
                                # backup ongoing
                                if status == cOP.BACKUP:
                                    log = f'receiving fileDirectoryName from {clientAddr}'

                                    server_log(
                                        userArray[userID], log)

                                    self.print_log(log)
                                    # receiving directory name
                                    dirName = clientSock.recv(1024)
                                    dirName = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], 
                                        dirName)
                                    # checking Directory
                                    log = f'receiving fileRequestOperand from {clientAddr}'
                                    self.check_dir(
                                        userArray[userID] + destDir + dirName)

                                    server_log(
                                        userArray[userID], log)

                                    self.print_log(log)
                                    req = clientSock.recv(16)
                                    req = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], req)
                                    if req == cOP.FILE:
                                        isDir = False
                                        self.handle_file(
                                            clientSock, clientAddr, userArray[userID] + destDir + dirName)
                                    elif req == cOP.BACKUP:
                                        log = f'recieved fileTransferStatus from {clientAddr}'

                                        server_log(
                                            userArray[userID], log)

                                        self.print_log(log)
                                        isDir = True
                                    else:

                                        server_log(
                                            userArray[userID], log)

                                        self.print_log(req)
                                # backup ongoing -> receiving file
                                elif status == cOP.FILE:
                                    self.handle_file(
                                        clientSock, clientAddr, userArray[userID] + destDir + dirName)
                                # backup complete
                                elif status == cOP.OK:
                                    self.debugger.debug(
                                        f"[{threading.get_ident()}] Backup finish initialized")
                                    userDir = userArray[userID] + \
                                        destDir + dirName
                                    currSize = self.get_size(
                                        userDir)
                                    # check that there was no data
                                    # loss
                                    log = f'checking directories {userDir} and {destDir}'
                                    end_check_ = self.end_check(
                                        dirSizeBefore, backupSize, destDir)

                                    server_log(
                                        userArray[userID], log)
                                    self.print_log(log)
                                    log = f'received status OK from {clientAddr}: received bytes'
                                    server_log(
                                        userArray[userID], log)

                                    self.print_log(log)
                                    if end_check_:
                                        # transfer finished
                                        fileTransfer = False
                                        log = f'file transfer finished from {clientAddr}'

                                        server_log(
                                            userArray[userID], log)

                                        self.print_log(log)
                                        clientSock.send(
                                            self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                                        clientSock.close()
                                        del self.crypt_clients_list[threading.get_ident()]
                                    else:
                                        # transfer incomplete
                                        fileTransfer = False
                                        message = f'server_side_error: endCheck failed. try backup again.'
                                        message = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], 
                                            message)
                                        clientSock.send(message)
                                        log = f'server_side_error: close connection to {clientAddr}'

                                        server_log(
                                            userArray[userID], log)

                                        self.print_log(log)
                                        clientSock.close()
                                        del self.crypt_clients_list[threading.get_ident()]
                                else:
                                    log = f'closing connection to {clientAddr}: closed by cient'

                                    server_log(
                                        userArray[userID], log)

                                    self.print_log(log)
                                    fileTransfer = False
                                    clientSock.close()
                                    del self.crypt_clients_list[threading.get_ident()]
                finally:
                    self.debugger.debug(
                        f"[{threading.get_ident()}] Trying to release client lock")
                    backup_client1_lock.release()
                    self.debugger.debug(
                        f"[{threading.get_ident()}] Trying to release client lock done")
                    clientSock.close()
                    del self.crypt_clients_list[threading.get_ident()]



        # download request
        elif data == cOP.DOWNLOAD:
            done = False
            # user identification --> necessary for client system path
            userID = self.user_config(clientSock, clientAddr)
            if userID not in (0, 1, 2, 3):
                error = f'closing connection to {clientAddr}: invalid auth_token'
                write_log(error)
                self.print_log(error)
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.FORBIDDEN))
                clientSock.close()
                del self.crypt_clients_list[threading.get_ident()]
            else:
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                transferType = clientSock.recv(1024)
                transferType = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], transferType)
                # download file
                if transferType == cOP.FILE:
                    # receiving file name
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                    fileName = clientSock.recv(1024)
                    fileName = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], fileName)
                    # search if file does exist
                    log = f'searching requestet file for {clientAddr}'
                    server_log(userArray[userID], log)
                    self.print_log(log)
                    for dirpath, dirnames, files in os.walk(
                            userArray[userID], topdown=False):
                        for file_name in files:
                            # file found
                            if file_name == fileName:
                                log = f'file found. sending to client {clientAddr}'

                                server_log(userArray[userID], log)

                                self.print_log(log)
                                # reading file data and sending to client
                                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                                filePath = dirpath + "/" + file_name
                                with open(filePath, 'rb') as clientFile:
                                    data = clientFile.read()
                                clientFile.close()
                                data = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], data, False)
                                fileSize = len(data)
                                fileSize = str(fileSize)
                                fileSize = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], fileSize)
                                clientSock.send(fileSize)
                                time.sleep(self.time_delay)
                                clientSock.send(data)
                                log = f'waiting for response from {clientAddr}'

                                server_log(userArray[userID], log)

                                self.print_log(log)
                                resp = clientSock.recv(16)
                                # check for data loss
                                resp = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], resp)
                                if resp == cOP.OK:
                                    log = f'OK recieved. closing connection to {clientAddr}'

                                    server_log(userArray[userID], log)

                                    self.print_log(log)
                                    clientSock.close()
                                    del self.crypt_clients_list[threading.get_ident()]
                                    done = True
                                    break
                                else:
                                    log = f'no response from {clientAddr}: closing connection'

                                    server_log(userArray[userID], log)

                                    self.print_log(log)
                                    clientSock.close()
                                    del self.crypt_clients_list[threading.get_ident()]
                                    done = True
                                    break
                # downloading directory
                elif transferType == cOP.DIR:
                    # receiving directory name
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                    dirName = clientSock.recv(1024)
                    dirName = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], dirName)
                    # check if directory does exist
                    log = f'searching requested directory for {clientAddr}'

                    server_log(userArray[userID], log)

                    self.print_log(log)
                    for dirpath, dirnames, files in os.walk(
                            userArray[userID], topdown=False):
                        for dir_name in dirnames:
                            if dir_name == dirName:
                                # directory found
                                dirpath = dirpath + '/'
                                log = f'directory {
                                    dirpath + dir_name} found. sending to client {clientAddr}'

                                server_log(userArray[userID], log)

                                self.print_log(log)
                                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                                time.sleep(self.time_delay)
                                # sending download size
                                backupSize = self.get_size(dirpath + dir_name)
                                backupSize = str(backupSize)
                                backupSize = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], backupSize)
                                clientSock.send(backupSize)
                                time.sleep(self.time_delay)
                                # sending directory
                                for dirpath, dirnames, filenames in os.walk(
                                        dirpath + dir_name, topdown=False):
                                    # sending transfer ongoing
                                    log = f"sending transferStatus to {clientAddr}"

                                    server_log(userArray[userID], log)

                                    self.print_log(log)
                                    clientSock.send(
                                        self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.TRANSFER))
                                    time.sleep(self.time_delay)
                                    dirpath = dirpath + '/'
                                    vPath = self.client1
                                    lenPath = len(vPath)
                                    dirpathSend = dirpath[lenPath:]
                                    # sending directory name
                                    log = f'sending directory name to {clientAddr}'

                                    server_log(userArray[userID], log)

                                    self.print_log(log)
                                    dirpathEncr = dirpathSend
                                    dirpathEncr = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], 
                                        dirpathEncr)
                                    clientSock.send(dirpathEncr)
                                    time.sleep(self.time_delay)
                                    # sending files
                                    for file_name in filenames:
                                        log = f'file {file_name} found. sending to client {clientAddr}'

                                        server_log(userArray[userID], log)

                                        self.print_log(log)
                                        clientSock.send(
                                            self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.FILE))
                                        time.sleep(self.time_delay)
                                        # sending file
                                        log = f'sending filename to {clientAddr}'

                                        server_log(userArray[userID], log)

                                        self.print_log(log)
                                        file_name_encr = file_name
                                        file_name_encr = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], 
                                            file_name_encr)
                                        clientSock.send(file_name_encr)
                                        time.sleep(self.time_delay)
                                        filePath = dirpath + "/" + file_name
                                        with open(filePath, 'rb') as clientFile:
                                            data = clientFile.read()
                                        clientFile.close()
                                        data = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], data, False)
                                        log = f'sending filesize to {clientAddr}'

                                        server_log(userArray[userID], log)

                                        self.print_log(log)
                                        fileSize = len(data)
                                        fileSize = str(fileSize)
                                        fileSize = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], fileSize)
                                        clientSock.send(fileSize)
                                        time.sleep(self.time_delay)
                                        log = f'receiving status from {clientAddr}'

                                        server_log(userArray[userID], log)

                                        self.print_log(log)
                                        status = clientSock.recv(16)
                                        status = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], status)
                                        self.debugger.debug("[%s] Received status %s"%(threading.get_ident(), status))
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
                                        resp = clientSock.recv(16)
                                        resp = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], resp)
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
                                            del self.crypt_clients_list[threading.get_ident()]
                                            break
                                        
                                # request completed
                                f'operation completed for client {clientAddr}'
                                server_log(userArray[userID], log)
                                self.print_log(log)
                                done = True
                                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.RST))
                                clientSock.close()
                                del self.crypt_clients_list[threading.get_ident()]
                                
                # wrong operand choosen from client
                else:
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.RST))
                    log = f'wrong operand from {clientAddr}'
                    write_log(log)
                    clientSock.close()
                    del self.crypt_clients_list[threading.get_ident()]
                if done:
                    pass
                else:
                    f'closing connection to {clientAddr}: could not locate file or directory'

                    server_log(userArray[userID], log)

                    self.print_log(log)
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.RST))
                    clientSock.close()
                    del self.crypt_clients_list[threading.get_ident()]
        # list filesystem request
        elif data == cOP.LISTFS:
            listfs = ''
            grep = ''
            # user identification --> necessary for client system path
            userID = self.user_config(clientSock, clientAddr)
            if userID not in (0, 1, 2, 3):
                error = f'closing connection to {clientAddr}: invalid auth_token'
                write_log(error)
                self.print_log(error)
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.RST))
                clientSock.close()
                del self.crypt_clients_list[threading.get_ident()]
            else:
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                outputType = clientSock.recv(1024)
                outputType = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], outputType)
                cut = len(userArray[userID])
                # sending client file system
                for dirpath, dirnames, files in os.walk(
                        userArray[userID], topdown=False):
                    listfs = listfs + (f' Directory: {dirpath[cut - 1:]} \r\n')
                    grep = grep + (f'Directory: {dirpath[cut - 1:]} \r\n')
                    for file_name in files:
                        listfs = listfs + \
                            (f'    \'----------> {file_name}\r\n')
                        grep = grep + \
                            (f'File: {dirpath[cut - 1:]}/{file_name} \r\n')
                log = f'sending filesystem to {clientAddr}'

                server_log(userArray[userID], log)

                self.print_log(log)
                time.sleep(self.time_delay)
                # custom output
                if outputType == cOP.LISTFS:
                    listfs = grep
                    listfs = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], listfs)
                    fileSize = len(listfs)
                    fileSize = str(fileSize)
                    fileSize = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], fileSize)
                    clientSock.send(fileSize)
                    time.sleep(self.time_delay)
                    clientSock.send(listfs)
                # grepable output
                elif outputType == cOP.GREP:
                    grep = grep
                    grep = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], grep)
                    fileSize = len(grep)
                    fileSize = str(fileSize)
                    fileSize = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], fileSize)
                    clientSock.send(fileSize)
                    time.sleep(self.time_delay)
                    clientSock.send(grep)
                # wrong operand choosen by client
                else:
                    log = f'recieved wrong operand'

                    server_log(userArray[userID], log)

                    self.print_log(log)
                    write_log(
                        f'recieved wrong listfs operand from {clientAddr}')
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.RST))
                    clientSock.close()
                    del self.crypt_clients_list[threading.get_ident()]
                # finish request
                log = f'waiting for OK from {clientAddr}'

                server_log(userArray[userID], log)

                self.print_log(log)
                recv = clientSock.recv(16)
                recv = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], recv)
                if recv == cOP.OK:
                    log = f'OK recieved. closing connection to {clientAddr}'

                    server_log(userArray[userID], log)

                    self.print_log(log)
                    clientSock.close()
                    del self.crypt_clients_list[threading.get_ident()]
        # remove data request
        elif data == cOP.REMOVE:
            # user identification --> necessary for client system path
            userID = self.user_config(clientSock, clientAddr)
            if userID not in (0, 1, 2, 3):
                error = f'closing connection to {clientAddr}: invalid auth_token'
                write_log(error)
                self.print_log(error)
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.RST))
                clientSock.close()
                del self.crypt_clients_list[threading.get_ident()]
            else:
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                # receiving name
                removeName = clientSock.recv(1024)
                removeName = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], removeName)
                # check for potential threat
                if not self.check_dir_sec(removeName):
                    log = f"WARNING: Detected potential security threat! {clientAddr}"

                    server_main_log(log)
                    log = f"WARNING: Attacker {clientAddr} tried to remove {removeName}"
                    server_main_log(log)

                    clientSock.close()
                    del self.crypt_clients_list[threading.get_ident()]
                else:
                    # remove file or directory if existing
                    if os.path.exists(userArray[userID] + removeName):
                        try:
                            os.remove(userArray[userID] + removeName)
                        except OSError:
                            shutil.rmtree(userArray[userID] + removeName)
                        log = f'removed {userArray[userID] + removeName}'

                        server_log(userArray[userID], log)

                        self.print_log(log)
                        clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                        clientSock.close()
                        del self.crypt_clients_list[threading.get_ident()]
                    else:
                        clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.NOT_FOUND))
                        log = f'file_not_found_error: {
                            userArray[userID] + removeName}'

                        server_log(userArray[userID], log)

                        self.print_log(log)
                        clientSock.close()
                        del self.crypt_clients_list[threading.get_ident()]
        # ping request
        elif data == cOP.PING:
            clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
            ping = f'sending ping request to {clientAddr}'

            server_main_log(ping)

            self.print_log(ping)
            self.print_log(f'closed connection to {clientAddr}')
            clientSock.close()
            del self.crypt_clients_list[threading.get_ident()]
        # reset
        elif data == cOP.RST:
            pass
        # client update request
        elif data == cOP.SERVERUPDATE:
            with open(self.client1 + 'ultron-server/uc', 'r') as file:
                data = file.read()
            file.close()
            data = data
            data = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], data)
            fileSize = len(data)
            fileSize = str(fileSize)
            fileSize = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], fileSize)
            clientSock.send(fileSize)
            time.sleep(self.time_delay)
            clientSock.send(data)
            updatedb = f'sending update to {clientAddr}: closing connection'

            server_main_log(updatedb)

            self.print_log(updatedb)
            clientSock.close()
            del self.crypt_clients_list[threading.get_ident()]
        # file system decryption request
        elif data == cOP.DECRYPT:
            key = clientSock.recv(1024)
            key = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], key)
            write_crypt_key(key)
            write_crypt_dir(self.client1)
            try:
                result = subprocess.run(
                    ['usdecrypt', ], capture_output=True, text=True)
                print(result.stdout)
                clientSock.send("[*] decryption completed")
            except Exception as e:
                print(e)
                write_log(e)
                clientSock.send("[-] decryption failed! output: ", e)
        # file system encryption request
        elif data == cOP.ENCRYPT:
            key = clientSock.recv(1024)
            key = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], key)
            write_crypt_key(key)
            write_crypt_dir(self.client1)
            try:
                result = subprocess.run(
                    ['usencrypt', ], capture_output=True, text=True)
                print(result.stdout)
                clientSock.send("[*] encryption completed")
            except Exception as e:
                print(e)
                write_log(e)
                clientSock.send("[-] encryption failed! output: ", e)
        # file upload request
        elif data == cOP.UPLOAD:
            # user identification --> necessary for client system path
            userID = self.user_config(clientSock, clientAddr)
            if userID not in (0, 1, 2, 3):
                error = f'closing connection to {clientAddr}: invalid auth_token'
                write_log(error)
                self.print_log(error)
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.FORBIDDEN))
                clientSock.close()
                del self.crypt_clients_list[threading.get_ident()]
            else:
                self.debugger.debug(
                    f"[{threading.get_ident()}] Trying to acquire lock")
                if backup_client1_lock.acquire(blocking=False):
                    self.debugger.debug(
                        f"[{threading.get_ident()}] Trying to acquire lock done")
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                else:
                    self.debugger.debug(
                        f"[{threading.get_ident()}] Waiting for client lock")
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.LOCK))
                    backup_client1_lock.acquire()
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                try:                # receiving file data
                    log = f'receiving file from {clientAddr}'

                    server_log(userArray[userID], log)

                    self.print_log(log)
                    fragmentCount = 0
                    fileDir = clientSock.recv(1024)
                    fileDir = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], fileDir)
                    if not self.check_dir_sec(fileDir):
                        log = f"WARNING: Detected potential security threat! {clientAddr}"

                        server_main_log(log)

                        clientSock.close()
                        del self.crypt_clients_list[threading.get_ident()]
                    else:
                        checkDir = self.fetch_dir(fileDir)
                        if checkDir == 'not available':
                            pass
                        else:
                            self.check_dir(userArray[userID] + checkDir)
                        log = f'recieved filedirectory from {clientAddr}'

                        server_log(userArray[userID], log)

                        self.print_log(log)
                        fileData = b''
                        time.sleep(self.time_delay)
                        filesize = clientSock.recv(1024)
                        filesize = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], filesize)

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
                            fileData += fileBytes
                            log = f'receiving bytes: {len(fileData)}/{filesize}'

                            server_log(userArray[userID], log)

                            self.print_log(log)
                            if filesize == len(fileData):
                                log = f'recieved bytes successfully from {clientAddr}'

                                server_log(userArray[userID], log)

                                self.print_log(log)
                                recieved = True
                                break
                        fileData = fileData
                        fileData = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], fileData, False)
                        filePath = userArray[userID] + fileDir
                        with open(filePath, 'wb') as openFile:
                            openFile.write(fileData)
                        openFile.close()
                        if recieved:
                            log = f'file from {clientAddr} written to  {filePath}'

                            server_log(userArray[userID], log)

                            self.print_log(log)
                            clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                            clientSock.close()
                            del self.crypt_clients_list[threading.get_ident()]
                        else:
                            log = f'filesize comparison went wrong. ERROR in {filesize}=={
                                os.path.getsize(filePath)}. closing connection to {clientAddr}'

                            server_log(userArray[userID], log)

                            self.print_log(log)
                            clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.RST))
                            clientSock.close()
                            del self.crypt_clients_list[threading.get_ident()]
                finally:
                    self.debugger.debug(
                        f"[{threading.get_ident()}] Trying to release client lock")
                    backup_client1_lock.release()
                    self.debugger.debug(
                        f"[{threading.get_ident()}] Trying to release client lock done")
                    clientSock.close()
                    del self.crypt_clients_list[threading.get_ident()]
        # token authentificaion request
        elif data == cOP.USERTOKEN:
            if self.authtoken_check(clientSock, clientAddr):
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                log = f'closing connection to {clientAddr}: job done'
                self.print_log(log)
                clientSock.close()
                del self.crypt_clients_list[threading.get_ident()]
            else:
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.RST))
                error = f'closing connection to {clientAddr}: token invalid'
                write_log(error)
                self.print_log(error)
                clientSock.close()
                del self.crypt_clients_list[threading.get_ident()]
        # ultron package installer
        # package request
        elif data == cOP.PACKAGE:
            # user identification --> necessary for client system path
            userID = self.user_config(clientSock, clientAddr)
            if userID not in (0, 1, 2, 3):
                error = f'closing connection to {clientAddr}: invalid auth_token'
                write_log(error)
                self.print_log(error)
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.FORBIDDEN))
                clientSock.close()
                del self.crypt_clients_list[threading.get_ident()]
            else:
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                # receiving package name
                package = clientSock.recv(1024)
                package = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], package)
                package_folder = userArray[userID] + \
                    '/ultron-server/packages/' + package
                log = f'searching requested package {package_folder} for {clientAddr}'

                server_log(userArray[userID], log)

                self.print_log(log)
                done = False
                # send package if existing
                if os.path.exists(package_folder):
                    log = f'package {package_folder} found. sending to client {clientAddr}'

                    server_log(userArray[userID], log)

                    self.print_log(log)
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                    time.sleep(self.time_delay)
                    backupSize = self.get_size(package_folder)
                    backupSize = str(backupSize)
                    backupSize = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], backupSize)
                    clientSock.send(backupSize)
                    time.sleep(self.time_delay)
                    for dirpath, dirnames, filenames in os.walk(
                            package_folder, topdown=False):
                        log = f"sending transferStatus to {clientAddr}"

                        server_log(userArray[userID], log)

                        self.print_log(log)
                        clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.TRANSFER))
                        time.sleep(self.time_delay)
                        dirpath = dirpath + '/'
                        vPath = self.client1
                        lenPath = len(vPath)
                        dirpathSend = dirpath[lenPath:]
                        log = f'sending directory name to {clientAddr}'

                        server_log(userArray[userID], log)

                        self.print_log(log)
                        dirpathEncr = dirpathSend
                        dirpathEncr = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], dirpathEncr)
                        clientSock.send(dirpathEncr)
                        time.sleep(self.time_delay)
                        for file_name in filenames:
                            log = f'file {file_name} found. sending to client {clientAddr}'

                            server_log(userArray[userID], log)

                            self.print_log(log)
                            clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.FILE))
                            time.sleep(self.time_delay)
                            log = f'sending filename to {clientAddr}'

                            server_log(userArray[userID], log)

                            self.print_log(log)
                            file_name_encr = file_name
                            file_name_encr = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], file_name_encr)
                            clientSock.send(file_name_encr)
                            time.sleep(self.time_delay)
                            filePath = dirpath + "/" + file_name
                            with open(filePath, 'rb') as clientFile:
                                data = clientFile.read()
                            clientFile.close()
                            data = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], data, False)
                            log = f'sending filesize to {clientAddr}'

                            server_log(userArray[userID], log)

                            self.print_log(log)
                            fileSize = len(data)
                            fileSize = str(fileSize)
                            fileSize = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], fileSize)
                            clientSock.send(fileSize)
                            time.sleep(self.time_delay)
                            log = f'receiving status from {clientAddr}'

                            server_log(userArray[userID], log)

                            self.print_log(log)
                            status = clientSock.recv(16)
                            status = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], status)
                            if status == cOP.OK:
                                log = f'sending bytes to {clientAddr}'

                                server_log(userArray[userID], log)

                                self.print_log(log)
                                clientSock.send(data)
                            else:
                                log = f'could not resolve status from {clientAddr}'

                                server_log(userArray[userID], log)

                                self.print_log(log)
                            self.print_log(
                                f'waiting for response from {clientAddr}')
                            resp = clientSock.recv(16)
                            resp = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], resp)
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
                                del self.crypt_clients_list[threading.get_ident()]
                                break
                    log = f'operation completed for client {clientAddr}'

                    server_log(userArray[userID], log)

                    self.print_log(log)
                    done = True
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.RST))
                else:
                    log = f'closing connection to {clientAddr}: could not locate package'

                    server_log(userArray[userID], log)

                    self.print_log(log)
                    clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.RST))
                    clientSock.close()
                    del self.crypt_clients_list[threading.get_ident()]
        # list all packages request
        elif data == cOP.LISTALL:
            # user identification --> necessary for client system path
            userID = self.user_config(clientSock, clientAddr)
            if userID not in (0, 1, 2, 3):
                error = f'closing connection to {clientAddr}: invalid auth_token'
                write_log(error)
                self.print_log(error)
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.FORBIDDEN))
                clientSock.close()
                del self.crypt_clients_list[threading.get_ident()]
            else:
                # sending package list
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                packageList = []
                versionList = []
                output = "Available packages:\r\n"
                for dirpath, dirnames, dirfiles in os.walk(
                        userArray[userID] + '/ultron-server/packages/'):
                    for name in dirnames:
                        packageList.append(name)
                    for filename in dirfiles:
                        if filename == "version.md":
                            with open(dirpath + "/" + filename, 'r') as f:
                                fileData = f.read()
                            f.close()
                            versionList.append(fileData)
                        else:
                            pass
                for x in range(len(packageList)):
                    output += f"""---------------------------------
package: {packageList[x]}
version: {versionList[x]}"""
                output = output + 33 * '-' + \
                    "\r\ntotal packages: " + str(len(packageList))
                log = f'sending list to {clientAddr}'

                server_log(userArray[userID], log)

                self.print_log(log)
                output = output
                output = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], output)
                time.sleep(self.time_delay)
                clientSock.send(output)
        # checks if package is available
        elif data == cOP.SEARCH:
            # user identification --> necessary for client system path
            userID = self.user_config(clientSock, clientAddr)
            if userID not in (0, 1, 2, 3):
                error = f'closing connection to {clientAddr}: invalid auth_token'
                server_log(userArray[userID], error)
                self.print_log(error)
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.FORBIDDEN))
                clientSock.close()
                del self.crypt_clients_list[threading.get_ident()]
            else:
                # sends package information if available
                clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.OK))
                data = clientSock.recv(1024)
                data = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], data)
                package = data
                version = ''
                packageAvailable = False
                for dirpath, dirnames, dirfiles in os.walk(
                        userArray[userID] + '/ultron-server/packages/'):
                    for filename in dirfiles:
                        if filename == package:
                            packageAvailable = True
                            with open(dirpath + "/version.md", 'r') as f:
                                version = f.read()
                            f.close()
                            info = f"""Package found!
name: {package}
version: {version}"""
                            info = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], info)
                            clientSock.send(info)
                            clientSock.close()
                            del self.crypt_clients_list[threading.get_ident()]
                        else:
                            pass
            if packageAvailable:
                pass
            else:
                info = f"Package {package} not found."
                info = self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], info)
                clientSock.send(info)
                clientSock.close()
                del self.crypt_clients_list[threading.get_ident()]
        else:
            clientSock.send(self.crypt_stub.encrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], cOP.RST))
            self.print_log(
                f'closed connection to {clientAddr}: wrong operand: {data}')
            write_log(
                f'closed connection to {clientAddr}: wrong operand: {data}')
            clientSock.close()
            del self.crypt_clients_list[threading.get_ident()]

    # Denial of Service protection

    def ddos_protection(self, current_date_time, clientAddr):
        # checks if protection already active
        if self.ddos_protection_active:
            pass
        else:
            # DDoS protection indicates a new thread which counts incoming connections
            # if the number of connections does exceed max_conn_number_ddos within 10 seconds the server
            # initializes shutdown and contacts the admin per mail about a
            # potential DDoS attack
            self.ddos_protection_active = True
            ddos = "[*] DDoS protection " + \
                colors.GREEN + "enabled" + colors.WHITE
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
                self.send_email(
                    self.targetEmail,
                    self.userEmail,
                    self.creditFile,
                    log)
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
            log = "\r\nConnecting to outlook-server [" + \
                colors.RED + "failed" + colors.WHITE + "]\r\n"
            server_main_log(log)

            print(log)
            pass
        log = "Connecting to outlook-server [" + \
            colors.GREEN, "done" + colors.WHITE, "]\r\n"

        server_main_log(log)

        print(log)
        msg = MIMEMultipart()
        msg['From'] = str("ULTRON-SERVER")
        msg['To'] = str(targetEmail)
        msg['Subject'] = str(
            "DDoS-Attack detected! DDoS-log is described in the message.")
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
        log = f'ultron-server version {server_version}'

        server_main_log(log)
        self.print_log(log)
        log = 'starting server...'
        server_main_log(log)
        self.print_log(log)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
                                              args=(current_date_time, clientAddr))
                ddosThread.start()
                clientThread = threading.Thread(target=self.handle_client,
                                                args=(clientSock, clientAddr))
                clientThread.daemon = True
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
            client_key, client_iv = self.crypt_stub.setup_encryption(clientSock)
            self.crypt_clients_list[threading.get_ident()] = (client_key, client_iv)
            log = f'waiting for request from {clientAddr}'

            server_main_log(log)
            self.print_log(log)
            option = clientSock.recv(16)
            option = self.crypt_stub.decrypt_data(self.crypt_clients_list[threading.get_ident()][0], self.crypt_clients_list[threading.get_ident()][1], option)
            log = f'request received from {clientAddr}'
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
        log = colors.YELLOW + "WARNING! Server shutdown initialized." + colors.WHITE

        server_main_log(log)

        self.print_log(log)
        self.sock.close()


# main function
def ultron_server():
    # fetching arguments
    if len(sys.argv) == 5 or len(sys.argv) == 6 or sys.argv[1] == '--updatedb':
        if sys.argv[1] == "--a":
            host = sys.argv[2]
        elif sys.argv[1] == "--updatedb":
            try:
                os.system("uc --u /ultron-server/us.py us")
                os.system("uc --u /ultron-server/server.cfg server.cfg")
                print("[*] Updated succesfully.")
            except Exception as error:
                print(colors.RED, error, colors.WHITE)
                print("[E] Update failed: ", error)
            sys.exit()
        if sys.argv[3] == "--p":
            port = sys.argv[4]
        else:
            print(
                f'version {server_version}\r\nusage: us --a [ADDRESS] --p [PORT]')
            sys.exit()
        try:
            if sys.argv[5] == "--debug":
                print("[*] Debugging enabled")
                debugger = Debug(enabled=True)
            else:
                print(
                    f'version {server_version}\r\nusage: us --a [ADDRESS] --p [PORT]')
                sys.exit()
        except Exception:
            debugger = Debug(enabled=False)
    else:
        print(
            f'version {server_version}\r\nusage: us --a [ADDRESS] --p [PORT]')
        sys.exit()
    # creating server object and starting ultron server
    server = TCPServer(host, int(port), debugger)
    server.configure_server()
    server.start_server()


# run ultron server
def main():
    # try:
    ultron_server()
    # except Exception as e:
    #    error = colors.RED + f'SERVER_ERROR: {e}' + colors.WHITE
    #    write_log(str(error))
    #    server_main_log(str(error))
    #    sys.exit(error)


if __name__ == "__main__":
    main()
