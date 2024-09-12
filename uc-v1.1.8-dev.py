#!/usr/bin/python3
# version 1.1.8

# import required modules
import os
import socket
import sys
import shutil
import threading
import time

from datetime import datetime
from getpass import getpass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

client_version = 'v1.1.8'


# class for coloured output
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
    ENCRPYT = "000"
    DECRYPT = "999"
    SEARCH = "876"
    LOCK = "503"



# debug class
class Debug:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def debug(self, message):
        if self.enabled:
            print(f"[DEBUG]: {message}")



# encryption stub
class EncryptionStub:
    def __init__(self):
        self.key = ""
        self.iv = 0

    def generate_ecdh_keys(self):
        client_private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend())
        client_public_key = client_private_key.public_key()
        return client_private_key, client_public_key

    def encrypt_data(self, plaintext, text=False):
        if text:
            plaintext = plaintext.encode('utf-8')
        cipher = Cipher(
            algorithms.AES(
                self.key), modes.CBC(
                self.iv), backend=default_backend())
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return ciphertext

    def decrypt_data(self, ciphertext, text=False):
        cipher = Cipher(
            algorithms.AES(
                self.key), modes.CBC(
                self.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        if text:
            return plaintext.decode('utf-8')
        return plaintext

    def setup_encryption(self, conn):
        server_public_bytes = conn.recv(1024)
        server_public_key = serialization.load_pem_public_key(
            server_public_bytes,
            backend=default_backend()
        )
        client_private_key, client_public_key = self.generate_ecdh_keys()
        client_public_bytes = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(client_public_bytes)
        shared_secret = client_private_key.exchange(
            ec.ECDH(), server_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32 + 16,  # 32 bytes for AES-256 key, 16 bytes for IV
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)
        self.key = derived_key[:32]
        self.iv = derived_key[32:48]

# client implementation


class TCPClient:

    # initializes TCPClient
    def __init__(self, host, port, debugger):
        # defines address and port
        self.serverAddr = host
        self.serverPort = port

        self.debugger = debugger

        # defines file paths
        self.keyfile = '/etc/ultron-server/key.txt'
        self.download = '/home/' + os.getlogin() + '/Documents/ultron-server/downloads/'
        self.package_path = '/etc/ultron-server/packages/'
        self.set_trigger = '/usr/bin/'

        # defines class variables for communication and output
        self.token = None
        self.key = 0
        self.iv = 0
        self.clientSock = None
        self.stop_thread = False
        self.thread_alive = False
        self.currSize = None
        self.currDownloadSize = 0
        self.percStatus = '0.00 %'
        self.current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.time_buffer = 0.3

    # prints output to stdout
    def print_log(self, msg):
        self.current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f'[{self.current_date_time}] {msg}')

    # tries to connect to the configured server
    def check_conn(self, serverAddr, serverPort):
        time.sleep(self.time_buffer)
        if self.connection_success:
            pass
        else:
            sys.exit()
        time.sleep(10)
        if self.connection_success:
            msg = 'connecting to server [' + str(serverAddr) + ']::[' + str(
                serverPort) + '] ' + colors.RED + 'failed' + colors.WHITE
            self.print_log(msg)
            self.print_log('ERROR: connection timed out')
            msg = 'server [' + colors.RED + 'offline' + colors.WHITE + ']'
            self.print_log(msg)
            sys.exit()
        else:
            pass

    # requests connection from server and returns True or False depending on
    # the server message
    def request_connection(self, serverAddr, serverPort):
        # creating socket
        self.current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('[' +
              str(self.current_date_time) +
              '] connecting to server [' +
              str(serverAddr) +
              ']::[' +
              str(serverPort) +
              '] ...', end='\r')
        try:
            # connecting to server
            self.clientSock.connect((serverAddr, serverPort))
            msg = 'connecting to server [' + str(serverAddr) + ']::[' + str(
                serverPort) + '] ' + colors.GREEN + 'done' + colors.WHITE
            self.print_log(msg)
            self.print_log(f'welcome to ultron server!')
            # connection established --> returning True
            return True
        except ConnectionRefusedError:
            # printing connection failed to stdout and closing socket
            msg = 'connecting to server [' + str(serverAddr) + ']::[' + str(
                serverPort) + '] ' + colors.RED + 'failed' + colors.WHITE
            self.print_log(msg)
            msg = 'server [' + colors.RED + 'offline' + colors.WHITE + ']'
            self.print_log(msg)
            self.clientSock.close()
            sys.exit()
        except Exception as error:
            # printing error to stdout and closing socket
            msg = 'connecting to server [' + str(serverAddr) + ']::[' + str(
                serverPort) + '] ' + colors.RED + 'failed' + colors.WHITE
            self.print_log(msg)
            self.print_log(error)
            self.clientSock.close()
            sys.exit()

    # encrypts data for communication
    # encrypts data for communication
    def generate_ecdh_keys(self):
        client_private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend())
        client_public_key = client_private_key.public_key()
        return client_private_key, client_public_key

    def generate_key_iv(self):
        key = os.urandom(32)  # Generate a 256-bit (32-byte) key
        iv = os.urandom(16)   # Generate a 128-bit (16-byte) IV
        return key, iv

    def encrypt_data(self, plaintext, text=True):
        if text:
            plaintext = plaintext.encode('utf-8')
        self.debugger.debug(f"Plaintext before encryption: {plaintext}")
        cipher = Cipher(
            algorithms.AES(
                self.key), modes.CBC(
                self.iv), backend=default_backend())
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        self.debugger.debug(f"Padded plaintext: {padded_plaintext}")
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        self.debugger.debug(f"Ciphertext: {ciphertext}")
        return ciphertext

    def decrypt_data(self, ciphertext, text=True):
        self.debugger.debug(f"Ciphertext before decryption: {ciphertext}")
        cipher = Cipher(
            algorithms.AES(
                self.key), modes.CBC(
                self.iv), backend=default_backend())
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
        self.debugger.debug(f"[{threading.get_ident()}] Start of encryption setup")
        server_public_bytes = conn.recv(1024)
        server_public_key = serialization.load_pem_public_key(
            server_public_bytes,
            backend=default_backend()
        )
        client_private_key, client_public_key = self.generate_ecdh_keys()
        self.debugger.debug(f"[{threading.get_ident()}] Serializing key pair to pem format done")
        client_public_bytes = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.debugger.debug(f"[{threading.get_ident()}] Sending client public key bytes to server")
        conn.sendall(client_public_bytes)
        shared_secret = client_private_key.exchange(
            ec.ECDH(), server_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32 + 16,  # 32 bytes for AES-256 key, 16 bytes for IV
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)
        aes_key = derived_key[:32]
        iv = derived_key[32:48]
        return aes_key, iv

    # returns size of directory
    def get_size(self, dir1):
        total_size = 0
        try:
            if os.listdir(dir1):
                for dirpath, dirnames, filenames in os.walk(dir1):
                    for f in filenames:
                        fp = os.path.join(dirpath, f)
                        # skip if it is symbolic link
                        if not os.path.islink(fp):
                            total_size += os.path.getsize(fp)
            else:
                pass
        except FileNotFoundError:
            pass
        return total_size

    # checks if some content is missing
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

    # rotating animation output while downloading
    # can be disabled to improve performance
    def exec_rotation(self, i, h):
        c1 = '/'
        c2 = '|'
        c3 = '\\'
        c4 = '—'
        rotation = ''
        c1i = i % 2
        cl3 = h % 4
        if int(cl3) == 0:
            return c4
        elif float(i).is_integer():
            return c2
        elif int(c1i) == 0:
            return c1
        else:
            return c3

    # progress bar when downloading files
    def print_load_filestatus(self, byteSize, fileSize):
        self.current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        percSize = int(byteSize) / int(fileSize)
        percSize *= 100
        percSize = round(percSize)
        hashtagCount = ''
        proccessOutput = ''
        percProccess = ''
        for i in range(101):
            if int(percSize) <= i:
                hashtagCount = i * '#'
                iCount = 100 - i
                proccessOutput = hashtagCount + iCount * '.'
                percProccess = f'{i}%'
                break
        output = f'[{self.current_date_time}] loading [{proccessOutput}] {percProccess}'
        print(output, end='\r')

    # progress bar when downloading directories
    def print_load_status(self, byteSize, fileSize,
                          destDir, dirSizeBefore, backupSize):
        self.current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        currSize = self.get_size(destDir)
        actSize = int(currSize) - int(dirSizeBefore)
        percSize = int(byteSize) / int(fileSize)
        percSize *= 100
        percSize = round(percSize)
        hashtagCount = ''
        proccessOutput = ''
        percProccess = ''
        for i in range(101):
            if int(percSize) <= i:
                hashtagCount = i * '#'
                iCount = 100 - i
                proccessOutput = hashtagCount + iCount * '.'
                percProccess = f'{i}%'
                break
        output = f'[{self.current_date_time}] loading [{proccessOutput}] {percProccess} || {self.percStatus}'
        print(output, end='\r')

    # returns server status
    def ping_request(self):
        self.key, self.iv = self.setup_encryption(self.clientSock)

        self.print_log(
            f'requesting ping from [{
                self.serverAddr}]::[{
                self.serverPort}]')
        self.clientSock.send(self.encrypt_data(cOP.PING))
        answ = self.clientSock.recv(16)
        ping = self.decrypt_data(answ)
        if ping == cOP.OK:
            self.print_log(
                'server [' +
                colors.GREEN +
                'online' +
                colors.WHITE +
                ']')
            self.clientSock.close()
            sys.exit
        else:
            self.print_log(
                'server [' + colors.RED + 'offline' + colors.WHITE + ']')
            self.clientSock.close()

    # downloads content from server
    def download_script(self, downloadType, downloadName, clientToken):
        self.key, self.iv = self.setup_encryption(self.clientSock)

        # requesting transfer
        self.print_log(
            f'requesting transfer from [{
                self.serverAddr}]::[{
                self.serverPort}]')
        self.clientSock.send(self.encrypt_data(cOP.DOWNLOAD))
        time.sleep(self.time_buffer)

        # authentication
        # sending client token
        clientToken = clientToken
        clientToken = self.encrypt_data(clientToken)
        self.clientSock.send(clientToken)
        resp = self.clientSock.recv(1024)
        resp = self.decrypt_data(resp)

        # receiving message from server
        if resp == cOP.OK:
            # authentification OK
            # downloading file
            if downloadType == 0:
                # sending file operand
                self.clientSock.send(self.encrypt_data(cOP.FILE))
                answ = self.clientSock.recv(16)
                answ = self.decrypt_data(answ)
                if answ == cOP.OK:
                    # transfer accepted
                    # sendig filename
                    fileNameEncr = downloadName
                    fileNameEncr = self.encrypt_data(fileNameEncr)
                    self.clientSock.send(fileNameEncr)
                    resp = self.clientSock.recv(1024)
                    resp = self.decrypt_data(resp)
                    if resp == cOP.OK:
                        skip = False
                        # sending filesize
                        filesize = self.clientSock.recv(1024)
                        filesize = self.decrypt_data(filesize)
                        filesize = filesize()
                        filesize = int(filesize)

                        # checking size of file
                        # if < 1024 then file will be send in one package
                        if filesize < 1024:
                            skip = True
                        fileData = b''

                        # if filesize higher than 1024, algorithm fetches all
                        # packages
                        while True:
                            if skip == True:
                                fileBytes = self.clientSock.recv(filesize)
                            else:
                                fileBytes = self.clientSock.recv(1024)
                            fileData += fileBytes
                            self.print_load_filestatus(len(fileData), filesize)
                            if int(filesize) == int(len(fileData)):
                                print('')
                                break
                            else:
                                pass

                        # decoding and decrypting content from server
                        fileData = fileData
                        fileData = self.decrypt_data(fileData, False)
                        download = self.download + downloadName

                        # writing download to file
                        check_dir(self.download)
                        with open(download, 'wb') as file:
                            file.write(fileData)
                        file.close()
                        self.print_log(
                            f'file written to {download}. closing connection')
                        self.clientSock.send(self.encrypt_data(cOP.OK))
                        self.clientSock.close()

                    # closing socket if file could not be found
                    elif resp == cOP.RST:
                        self.print_log(
                            f'file_not_found_error: closing connection to [{
                                self.serverAddr}]::[{
                                self.serverPort}]')
                        self.clientSock.close()

                # closing socket if selected operand is not available
                else:
                    self.print_log(
                        'ERROR: wrong operand. permission denied from server')
                    self.clientSock.close()

            # downloads directoriy and its subdirectories
            elif downloadType == 1:
                # sending directory operand
                self.clientSock.send(self.encrypt_data(cOP.DIR))

                # variable to handle transfer
                transferDone = False

                # receieving answer from server
                answ = self.clientSock.recv(16)
                answ = self.decrypt_data(answ)
                self.print_log(f'writing changes to {self.download}')

                # handling answer
                if answ == cOP.OK:
                    # transfer accepted
                    # sending directory name
                    dirNameEncr = downloadName
                    dirNameEncr = self.encrypt_data(dirNameEncr)
                    self.clientSock.send(dirNameEncr)
                    found = self.clientSock.recv(1024)
                    found = self.decrypt_data(found)

                    # directory found?
                    if found == cOP.OK:
                        # yes
                        # receiving size of directory
                        backupSize = self.clientSock.recv(1024)
                        backupSize = self.decrypt_data(backupSize)
                        # variables to handle download in the next step
                        dirSizeBefore = 0
                        ogDirSize = self.get_size(self.download + downloadName)
                        pathName = None
                        transferVar = False

                        # receieving content
                        while not transferDone:
                            # receiev answer form server if download is
                            # finished
                            if not transferVar:
                                answ = self.clientSock.recv(16)
                                answ = self.decrypt_data(answ)
                            else:
                                answ = cOP.TRANSFER
                                transferVar = False

                            # transfer is still going on
                            if answ == cOP.TRANSFER or answ == cOP.FILE:
                                # receieving directory name
                                if answ == cOP.TRANSFER:
                                    pathName = self.clientSock.recv(1024)
                                    pathName = self.decrypt_data(pathName)
                                    fileStatus = self.clientSock.recv(1024)
                                    fileStatus = self.decrypt_data(fileStatus)
                                else:
                                    fileStatus = cOP.FILE

                                # receieving file
                                if fileStatus == cOP.FILE:
                                    skip = False

                                    # receieving file name
                                    fileName = self.clientSock.recv(1024)
                                    fileName = self.decrypt_data(fileName)
                                    destDir = self.download + pathName
                                    check_dir(destDir)
                                    dirSizeBefore = self.get_size(destDir)

                                    # receieving file size
                                    filesize = self.clientSock.recv(1024)
                                    filesize = self.decrypt_data(filesize)
                                    filesize = int(filesize)

                                    # checking size of file
                                    if filesize < 1024:
                                        skip = True
                                    fileData = b''
                                    self.clientSock.send(
                                        self.encrypt_data(cOP.OK))

                                    # if filesize higher than 1024, algorithm
                                    # fetches all packages
                                    while True:
                                        if skip == True:
                                            fileBytes = self.clientSock.recv(
                                                filesize)
                                        else:
                                            fileBytes = self.clientSock.recv(
                                                1024)
                                        fileData += fileBytes
                                        self.print_load_status(
                                            len(fileData), filesize, destDir, dirSizeBefore, backupSize)
                                        if int(filesize) == int(len(fileData)):
                                            break
                                        else:
                                            pass

                                    # decrypting bytes from server
                                    fileData = fileData
                                    fileData = self.decrypt_data(fileData, False)
                                    download = self.download + pathName + fileName

                                    # writing files
                                    with open(download, 'wb') as file:
                                        file.write(fileData)
                                    file.close()

                                    # printing log to stdout
                                    logName = pathName + fileName
                                    self.currDownloadSize = self.currDownloadSize + \
                                        len(fileData)
                                    self.percStatus = self.currDownloadSize / \
                                        int(backupSize)
                                    self.percStatus *= 100
                                    self.percStatus = '{:.2f}'.format(
                                        self.percStatus)
                                    self.percStatus = f'{self.percStatus}%'
                                    self.current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                    log = f'[{self.current_date_time}] file written to {logName}.'
                                    lengthPath = len(log)
                                    if lengthPath > 150:
                                        count = 0
                                    else:
                                        count = 150 - lengthPath
                                    space = count * ' '
                                    log += space
                                    print(log)
                                    self.current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                    log = f'[{self.current_date_time}] download progress [{self.percStatus}]'
                                    print(log, end='\r')

                                    # sending "file received" message to server
                                    self.clientSock.send(
                                        self.encrypt_data(cOP.OK))

                                # transfer goes on
                                else:
                                    transferVar = True

                            # download finished
                            elif answ == cOP.RST:
                                # checking if content is missing
                                if self.end_check(
                                        ogDirSize, backupSize, destDir):
                                    # all fine
                                    self.print_log(
                                        'job done. quitting            ')
                                    transferDone = True
                                    self.clientSock.close()
                                else:
                                    # something is missing
                                    self.print_log(
                                        '\r\nERROR: end_check failed: download incomplete')
                                    self.clientSock.close()

                            # connection interrupted
                            else:
                                self.print_log(
                                    '\r\nSERVER_SIDE_ERROR: closing connection.')
                                self.clientSock.close()
                                transferDone = True

                    # directory not found
                    else:
                        self.print_log(
                            f'directory_not_found_error: closing connection to [{
                                self.serverAddr}]::[{
                                self.serverPort}]')
                        self.clientSock.close()

        # authentification failure
        elif resp == cOP.FORBIDDEN:
            self.print_log('403 forbidden: invalid token')
            self.clientSock.close()

        # server offline
        else:
            self.print_log(
                'server [' + colors.RED + 'offline' + colors.WHITE + ']')
            self.clientSock.close()

    # script to perform a complete scan of the client filesystem on the server

    def listfs(self, clientToken, oFile):
        self.key, self.iv = self.setup_encryption(self.clientSock)

        # requesting list and sending operand
        self.print_log(
            f'requesting listfs from [{
                self.serverAddr}]::[{
                self.serverPort}]')
        self.clientSock.send(self.encrypt_data(cOP.LISTFS))
        time.sleep(self.time_buffer)

        # sending client token
        clientToken = str(clientToken)
        clientToken = self.encrypt_data(clientToken)
        self.clientSock.send(clientToken)

        # receiving answer from server
        answ = self.clientSock.recv(16)
        answ = self.decrypt_data(answ)

        # answer OK?
        if answ == cOP.RST:
            # no
            # closing socket
            self.print_log(
                f'connection refused by [{
                    self.serverAddr}]::[{
                    self.serverPort}]')
            self.clientSock.close()
        elif answ == cOP.OK:
            # yes
            # sending operands depending on outputfile
            if oFile == 'NULL':
                # no output file
                self.clientSock.send(self.encrypt_data(cOP.LISTFS))
            else:
                # output file
                self.clientSock.send(self.encrypt_data(cOP.GREP))

            # algorithm to receive all packages
            fragmentCount = 0
            filesize = self.clientSock.recv(1024)
            filesize = self.decrypt_data(filesize)

            filesize = int(filesize)
            fileData = b''
            current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            if filesize > 1448:
                fragmentCount = filesize / 1448
                fragmentCount += 1
            else:
                fragmentCount = 1
            for i in range(int(fragmentCount)):
                fileBytes = self.clientSock.recv(1500)
                fileData += fileBytes
                self.print_load_filestatus(len(fileData), filesize)
                if filesize == len(fileData):
                    print(
                        f'[{current_date_time}] recieved bytes successfully     ', end='\r')
                    break

            # decoding and decrypting received data
            fileData = fileData
            fileData = self.decrypt_data(fileData)

            # handling output
            if oFile == "NULL":
                # no output file
                # printing to stdout
                self.print_log('recieved filesystem:\r\n')
                print(fileData)
            else:
                # writing data to output file
                with open(self.download + oFile, 'w') as file:
                    file.write(fileData)
                file.close()
                space = 120 * " "
                self.print_log(
                    f'filesystem written to {
                        self.download +
                        oFile}{space}')

            # sending operation done and closing socket
            self.clientSock.send(self.encrypt_data(cOP.OK))
            self.clientSock.close()

    # script to verify authentification token

    def test_authtoken(self, clientToken):
        self.key, self.iv = self.setup_encryption(self.clientSock)

        # requesting token validation
        self.print_log(
            f'requesting token validation from [{
                self.serverAddr}]::[{
                self.serverPort}]')
        self.clientSock.send(self.encrypt_data(cOP.USERTOKEN))
        time.sleep(self.time_buffer)

        # sending user token
        clientToken = str(clientToken)
        clientToken = self.encrypt_data(clientToken)
        self.clientSock.send(clientToken)

        # revceiving answer from server
        integrity = self.clientSock.recv(1024)

        # token valid?
        if integrity == cOP.OK:
            # yes
            # printing to stdout and closing socket
            self.print_log('auth_token valid')
            self.clientSock.close()
        elif integrity == cOP.RST:
            # no
            # printing to stdout and closing socket
            self.print_log(
                'auth_token invalid. Please contact the administrator for a new token')
            self.clientSock.close()
        else:
            # something went wrong. closing socket
            self.print_log(
                'could not resolve answer from server. closing connection')
            self.clientSock.close()

    # script to update client

    def updateuc(self):
        self.key, self.iv = self.setup_encryption(self.clientSock)

        # requesting update
        self.print_log(
            f'updating uc from [{
                self.serverAddr}]::[{
                self.serverPort}]')
        self.clientSock.send(self.encrypt_data(cOP.SERVERUPDATE))

        # receieving file size
        filesize = self.clientSock.recv(1024)
        filesize = self.decrypt_data(filesize)

        filesize = int(filesize)
        fileData = b''

        # reveiving bytes
        while True:
            fileBytes = self.clientSock.recv(1024)
            fileData += fileBytes
            self.print_load_filestatus(len(fileData), filesize)
            if int(filesize) == int(len(fileData)):
                break
            else:
                pass

        # decoding and decrypting bytes
        fileData = fileData
        fileData = self.decrypt_data(fileData)
        # writing update to file
        with open('/usr/bin/uc', 'w') as file:
            file.write(fileData)
        file.close()

        # printing to stdout and closing socket
        self.print_log('\nupdated successfully')
        self.clientSock.close()

    # script to upload a single file

    def upload_script(self, fileDirectory, userFile, userToken):
        self.key, self.iv = self.setup_encryption(self.clientSock)

        # requesting file upload
        current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.print_log(
            f'requesting file transfer from [{
                self.serverAddr}]::[{
                self.serverPort}]')
        self.clientSock.send(self.encrypt_data(cOP.UPLOAD))
        time.sleep(self.time_buffer)

        # sending user token
        userToken = str(userToken)
        userToken = self.encrypt_data(userToken)
        self.clientSock.send(userToken)

        # receiving ansewer from server
        answ = self.clientSock.recv(16)
        answ = self.decrypt_data(answ)
        
            # trying to acquire write access to the client data
        if answ == cOP.LOCK:
                self.print_log(
                    f'WARNING: acquiring lock failed. Client resources already in use. Please wait.')
                answ = self.clientSock.recv(16)
                answ = self.decrypt_data(answ)
                if answ == cOP.OK:
                    answ = True
        elif answ == cOP.OK:
                answ = True
        else:
                self.print_log("ERROR: backup failed: ", answ)
                self.clientSock.close()
                sys.exit()

            # analysing answer
        if answ:
            # yes
            # upload approved
            print(f'[{current_date_time}] sending file...', end='\r')

            # sending fileDirectory
            time.sleep(self.time_buffer)
            fileDirectory = str(fileDirectory)
            fileDirectory = self.encrypt_data(fileDirectory)
            self.clientSock.send(fileDirectory)
            with open(userFile, 'rb') as file:
                data = file.read()
            file.close()
            data = self.encrypt_data(True, data)

            # sending filesize
            fileSize = len(data)
            fileSize = str(fileSize)
            fileSize = self.encrypt_data(fileSize)
            self.clientSock.send(fileSize)
            time.sleep(self.time_buffer)

            # reveiving answer from server
            self.clientSock.send(data)
            answ = self.clientSock.recv(16)
            answ = self.decrypt_data(answ)
            # analyse answer
            if answ == cOP.OK:
                self.print_log('sending file   done')
                self.clientSock.close()
            elif answ == cOP.RST:
                self.print_log('sending file   failed')
            else:
                self.print_log(
                    'could not resolve answer from server. quitting')
                self.clientSock.close()

        else:
            self.print_log('ERROR: could not upload file: ', answ)
            self.clientSock.close()

    # script to remove content from server
    def remove_script(self, removeName, userToken):
        self.key, self.iv = self.setup_encryption(self.clientSock)

        # sending request to server
        self.print_log(
            f'requesting removal from [{
                self.serverAddr}]::[{
                self.serverPort}]')
        self.clientSock.send(self.encrypt_data(cOP.REMOVE))
        time.sleep(self.time_buffer)

        # sending user token for authentification
        userToken = str(userToken)
        userToken = self.encrypt_data(userToken)
        self.clientSock.send(userToken)

        # reveiving answer from server
        answ = self.clientSock.recv(16)
        answ = self.decrypt_data(answ)
        # analyse answer
        if answ == cOP.OK:
            # sending file or directory name to remove
            removePath = removeName
            removeName = removeName
            removeName = self.encrypt_data(removeName)

            # receiving answer
            self.clientSock.send(removeName)
            answ = self.clientSock.recv(16)
            answ = self.decrypt_data(answ)

            # analysing answer
            if answ == cOP.OK:
                self.print_log(f'removed {removePath}')
                self.clientSock.close()
            elif answ == cOP.NOT_FOUND:
                self.print_log(
                    f'ERROR: file_not_found_error: could not locate {removePath}')
                self.clientSock.close()

    # script to backup directory to server
    def backup_script(self, srcDirectory, dstDirectory, clientToken):
        self.key, self.iv = self.setup_encryption(self.clientSock)
        # function to count size directory

        def get_size(dir1):
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(dir1):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    # skip if it is symbolic link
                    if not os.path.islink(fp):
                        total_size += os.path.getsize(fp)
            return total_size

        # loading animation while backup is pending
        def print_loading_backup():
            h = 4
            i = 2.5
            while True:
                rot = self.exec_rotation(i, h)
                h += 1
                i += 0.5
                self.current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(
                    '[' +
                    self.current_date_time +
                    '] preparing backup ',
                    rot,
                    end='\r')
                if self.stop_thread:
                    break

        # progress status in percent while sending content
        def print_punct():
            while True:
                self.current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if self.stop_thread:
                    break
                print(f'[{self.current_date_time}]',
                      'sending files .    (', self.currSize, '%)', end='\r')
                time.sleep(0.5)
                print(f'[{self.current_date_time}]',
                      'sending files ..   (', self.currSize, '%)', end='\r')
                time.sleep(0.5)
                print(f'[{self.current_date_time}]',
                      'sending files ...  (', self.currSize, '%)', end='\r')
                time.sleep(0.5)
                print(f'[{self.current_date_time}]',
                      'sending files      (', self.currSize, '%)', end='\r')
                time.sleep(0.5)

        # animation while sending content
        def print_process(sentBytes):
            self.stop_thread = False
            current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            dirSize = get_size(srcDirectory)
            self.currSize = sentBytes / dirSize * 100
            self.currSize = '{:.2f}'.format(self.currSize)
            if self.thread_alive:
                pass
            else:
                punct = threading.Thread(target=print_punct)
                punct.start()
                self.thread_alive = True
            if float(self.currSize) == 100.00:
                self.stop_thread = True
                self.thread_alive = False

        # main function of backups script
        def send_backup():
            # requesting file transfer
            sentBytes = 0
            self.print_log(
                f'requesting file transfer from [{
                    self.serverAddr}]::[{
                    self.serverPort}]')
            self.clientSock.send(self.encrypt_data(cOP.BACKUP))
            time.sleep(self.time_buffer)

            # sending user token for authentification
            userToken = str(clientToken)
            userToken = self.encrypt_data(userToken)
            self.clientSock.send(userToken)

            # receiving answer from server
            answ = self.clientSock.recv(16)
            answ = self.decrypt_data(answ)

            # trying to acquire write access to the client data
            if answ == cOP.LOCK:
                self.print_log(
                    f'WARNING: acquiring lock failed. Client resources already in use. Please wait.')
                answ = self.clientSock.recv(16)
                answ = self.decrypt_data(answ)
                if answ == cOP.OK:
                    answ = True
            elif answ == cOP.OK:
                answ = True
            else:
                self.print_log("ERROR: backup failed: ", answ)
                self.clientSock.close()
                sys.exit()

            # analysing answer
            if answ:
                rot = threading.Thread(target=print_loading_backup)
                rot.start()

                # sending destination directory name to server
                dstDirEncr = str(dstDirectory)
                dstDirEncr = self.encrypt_data(dstDirEncr)
                self.clientSock.send(dstDirEncr)
                time.sleep(self.time_buffer)

                # check if directory exists
                if os.path.exists(str(srcDirectory)):
                    pass
                else:
                    self.print_log(f'ERROR: could not locate {srcDirectory}')
                    self.clientSock.close()
                    sys.exit()

                # sending backupsize
                backupSize = get_size(srcDirectory)
                backupSize = str(backupSize)
                backupSize = self.encrypt_data(backupSize)
                self.clientSock.send(backupSize)
                time.sleep(self.time_buffer)

                # sending source directory name
                srcDirectoryEncr = srcDirectory
                srcDirectoryEncr = self.encrypt_data(srcDirectoryEncr)
                self.clientSock.send(srcDirectoryEncr)
                time.sleep(self.time_buffer)

                # sending directories and its files to the server
                cut = len(srcDirectory)
                for dirpath, dirnames, files in os.walk(srcDirectory):
                    # sending status
                    time.sleep(self.time_buffer)
                    self.clientSock.send(self.encrypt_data(cOP.BACKUP))

                    # sending directory name
                    dirpath = dirpath + '/'
                    dirpathEncr = str(dirpath)
                    dirpathEncr = self.encrypt_data(dirpathEncr)
                    self.clientSock.send(dirpathEncr)
                    time.sleep(self.time_buffer)

                    # handling files and directories
                    for fileName in files:
                        # sending fileOperand
                        time.sleep(self.time_buffer)
                        self.clientSock.send(self.encrypt_data(cOP.FILE))
                        
                        answ = self.clientSock.recv(16)
                        answ = self.decrypt_data(answ)
                        
                        if answ != cOP.OK:
                            self.print_log("ERROR: failed to sent file: ", answ) 
                        else:
                            # sending fileName
                            fileNameEncr = str(fileName)
                            fileNameEncr = self.encrypt_data(fileNameEncr)
                            self.clientSock.send(fileNameEncr)
                            time.sleep(self.time_buffer)

                            # reading file data
                            self.debugger.debug(f"open file {dirpath}{fileName}")
                            with open(dirpath + fileName, 'rb') as fileOpen:
                                fileBytes = fileOpen.read()
                            fileOpen.close()

                            self.debugger.debug(f"[{threading.get_ident()}] Sending file size of unencrypted file bytes")
                            # sending fileSize of unencrypted file
                            fileSize = len(fileBytes)
                            fileSize = str(fileSize)
                            fileSize = self.encrypt_data(fileSize)
                            self.clientSock.send(fileSize)
                            time.sleep(self.time_buffer)

                            # printing process
                            sentBytes += len(fileBytes)
                            self.stop_thread = True
                            rot.join()
                            print_process(sentBytes)

                            # sending bytes
                            self.debugger.debug(f"encrypting bytes {fileBytes}")
                            fileBytes = self.encrypt_data(fileBytes, False)

                            # sending filesize of encrypted file
                            fileBytesSize = len(fileBytes)
                            fileBytesSize = str(fileBytesSize)
                            self.debugger.debug(
                                f"sending filebytesize {fileBytesSize}")
                            fileBytesSize = self.encrypt_data(fileBytesSize)
                            self.clientSock.send(fileBytesSize)
                            time.sleep(self.time_buffer)
                            self.debugger.debug(f"sending filebytes {fileBytes}")
                            self.clientSock.send(fileBytes)
                            time.sleep(self.time_buffer)

                            # waiting for OK from server
                            status = self.clientSock.recv(16)
                            status = self.decrypt_data(status)
                            if status == cOP.OK:
                                pass
                            else:
                                self.print_log(f'message from server: {status}')

                # transfer finished
                self.debugger.debug(f"[{threading.get_ident()}] sending transfer finished flag")
                self.clientSock.send(self.encrypt_data(cOP.OK))
                time.sleep(self.time_buffer)

                # end check to verify that no data has been lost
                endCheck = self.clientSock.recv(16)
                endCheck = self.decrypt_data(endCheck)
                if endCheck == cOP.OK:
                    self.print_log('backup completed. quitting      ')
                    self.clientSock.close()
                    sys.exit()
                else:
                    self.print_log(f'message from server: {endCheck}')
                    self.clientSock.close()

            # connection refused by server
            elif answ == cOP.RST():
                self.print_log('connection refused')
                self.clientSock.close()

            # server unreachable
            else:
                self.print_log('could not resolve response. QUITTING')
                self.clientSock.close()

        # error handling
        try:
            send_backup()
        except Exception as e:
            print(e)

    # script to encrypt all content stored on the server

    def crypt(self):
        # retrieve encryption key from user
        self.print_log("---encryption/decryption mode---")
        key = getpass("Enter key: ")
        key = key
        key = self.encrypt_data(key)
        answ = input("Do you want to (e)ncrypt or (d)ecrypt your data? »» ")

        # decryption
        if answ in "d, D":
            self.print_log("Decrypting your data. This may take a while...")
            self.key, self.iv = self.setup_encryption(self.clientSock)
            self.clientSock.send(self.encrypt_data(cOP.decrpyt))
            time.sleep(self.time_buffer)
            self.clientSock.send(key)

        # encryption
        elif answ in "e, E":
            self.print_log("Encrypting your data. This may take a while...")
            self.clientSock.send(self.encrypt_data(cOP.ENCRYPT))
            time.sleep(self.time_buffer)
            self.clientSock.send(key)

        # wrong input
        else:
            sys.exit("ERROR: invalid option detected")

        # receive server answer
        recv = self.clientSock.recv(16)
        recv = self.decrypt_data(recv)
        self.print_log(recv)
        self.clientSock.close()

    # script to install packages
    def install(self, userToken, package):
        self.key, self.iv = self.setup_encryption(self.clientSock)

        # installs package on system
        def install_package(package):
            # copies file to binaries /usr/bin
            package_path_complete = self.package_path + package + '/'
            setup_path = package_path_complete + 'setup.py'
            self.print_log('installing triggers')
            shutil.copy(package_path_complete + package, '/usr/bin/' + package)

            # sets file to executable
            os.system(f'chmod +x /usr/bin/{package}')

            # runs setup script if available
            if os.path.exists(setup_path):
                self.print_log('running setup.py')
                os.system('python3 ' + setup_path)
            else:
                pass

        # request package from server
        self.print_log(
            f'installing package from [{
                self.serverAddr}]::[{
                self.serverPort}]')
        self.clientSock.send(self.encrypt_data(cOP.PACKAGE))
        time.sleep(self.time_buffer)

        # sending token for authentification
        userToken = str(userToken)
        userToken = self.encrypt_data(userToken)
        self.clientSock.send(userToken)

        # receiving answer
        answ = self.clientSock.recv(16)
        answ = self.decrypt_data(answ)

        # handling answer
        if answ == cOP.OK:
            # sending package name
            pkgencr = package
            pkgencr = self.encrypt_data(pkgencr)

            # receiving answer
            self.clientSock.send(pkgencr)
            answ = self.clientSock.recv(16)
            answ = self.decrypt_data(answ)

            # package not found
            if answ != cOP.OK:
                self.print_log(f'requested package {package} not found')

            # package found
            else:
                # check if directory already exists
                check_dir(self.package_path + package + '/')

                # receive package size
                pkgsize = self.clientSock.recv(1024)
                pkgsize = self.decrypt_data(pkgsize)

                # variables for transfer
                transferDone = False
                transferVar = False
                current_package_size = 0
                i = 2.5
                h = 4

                # handling transfer
                while not transferDone:

                    # receive status from server
                    if not transferVar:
                        answ = self.clientSock.recv(16)
                        self.decrypt_data(answ)

                    # set transfer to ongoing
                    else:
                        answ = cOP.TRANSFER
                        transferVar = False

                    # transfer ongoing
                    if answ == cOP.TRANSFER or answ == cOP.FILE:

                        # receiving path name for package
                        if answ == cOP.TRANSFER:
                            pathName = self.clientSock.recv(1024)
                            pathName = self.decrypt_data(pathName)
                            check_dir('/etc/' + pathName)
                            fileStatus = self.clientSock.recv(1024)
                            fileStatus = self.decrypt_data(fileStatus)

                        # set file status to file
                        else:
                            fileStatus = cOP.FILE

                        # handling file
                        if fileStatus == cOP.FILE:
                            # receiving file name
                            fileName = self.clientSock.recv(1024)
                            fileName = self.decrypt_data(fileName)

                            # set file destination
                            destDir = self.package_path + package + '/'

                            # get size of destination directory
                            dirSizeBefore = self.get_size(destDir)

                            # receive file size
                            filesize = self.clientSock.recv(1024)
                            filesize = self.decrypt_data(filesize)

                            filesize = int(filesize)
                            fileData = b''
                            current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                            # send status OK
                            self.clientSock.send(self.encrypt_data(cOP.OK))

                            # receive file bytes
                            while True:
                                fileBytes = self.clientSock.recv(1024)
                                fileData += fileBytes
                                current_package_size += len(fileData)
                                currSize = (
                                    int(current_package_size) / int(pkgsize)) * 100
                                percsize = '{:.2f}'.format(currSize)
                                rotation = self.exec_rotation(i, h)
                                h += 1
                                i += 0.5
                                print(
                                    '[' +
                                    self.current_date_time +
                                    ']' +
                                    ' loading package ' +
                                    rotation,
                                    end=('\r'))
                                if int(filesize) == int(len(fileData)):
                                    break
                                else:
                                    pass

                            # decrypt file data
                            fileData = fileData
                            fileData = self.decrypt_data(fileData, False)

                            # write file
                            download = '/etc/' + pathName + fileName
                            with open(download, 'wb') as file:
                                file.write(fileData)
                            file.close()
                            self.clientSock.send(self.encrypt_data(cOP.OK))

                        # set transfer to ongoing
                        else:
                            transferVar = True

                    # download complete
                    elif answ == cOP.RST:
                        self.print_log('package download complete')
                        transferDone = True
                        self.clientSock.close()
                        install_package(package)
                        self.print_log(
                            f'[+] package {package} installed successfully.')

                    # server side error
                    else:
                        self.print_log(
                            'SERVER_SIDE_ERROR: closing connection.')
                        self.clientSock.close()
                        transferDone = True

        # package not found
        else:
            self.print_log(f'{package} package not found.')
            self.clientSock.close()

    # script to list all available packages
    def listall(self, userToken):
        self.key, self.iv = self.setup_encryption(self.clientSock)
        # request to list available packages
        self.print_log(
            f'listing available packages from [{
                self.serverAddr}]::[{
                self.serverPort}]')
        self.clientSock.send(self.encrypt_data(cOP.LISTALL))
        time.sleep(self.time_buffer)

        # sending user token for authentification
        userToken = str(userToken)
        userToken = self.encrypt_data(userToken)
        self.clientSock.send(userToken)

        # receiving answer
        answ = self.clientSock.recv(16)
        answ = self.decrypt_data(answ)
        endData = ''

        # analysing answer
        if answ == cOP.OK:

            # receiving bytes
            while True:
                data = self.clientSock.recv(1024)
                endData += data
                if len(data) < 1024:
                    break

            # decrypting data
            data = self.decrypt_data(endData)

            # printing list of available packages
            print(data)
            self.clientSock.close()
            sys.exit()

        # authentification token is invalid
        else:
            self.print_log("invalid token")
            sys, exit()

    # checks if package already installed on system
    def check_install(self, package):
        if os.path.exists(self.package_path + package):
            self.print_log(f"[*] package {package} already installed.")
            sys.exit()
        else:
            pass

    # removes package from system
    def remove(self, package):
        self.key, self.iv = self.setup_encryption(self.clientSock)
        try:
            shutil.rmtree(self.package_path + package)
            os.remove("/usr/bin/" + package)
            self.print_log(f"[*] removed package {package} succesfully.")
        except PermissionError:
            self.print_log('ERROR: Permission denied. Are you root?')
        except Exception as e:
            self.print_log(f'ERROR: {package} package not found.')

    # script to return if package is available
    def search(self, userToken, package):
        self.key, self.iv = self.setup_encryption(self.clientSock)
        # request package search
        self.print_log(
            f"searching available package from [{
                self.serverAddr}]::[{
                self.serverPort}]")
        self.clientSock.send(self.encrypt_data(cOP.SEARCH))
        time.sleep(self.time_buffer)

        # sending authentifiction token
        userToken = str(userToken)
        userToken = self.encrypt_data(userToken)
        self.clientSock.send(userToken)

        # receiving answer
        answ = self.clientSock.recv(16)
        answ = self.decrypt_data(answ)
        endData = ''

        # anaylising answer
        if answ == cOP.OK:
            # sending package name
            package = self.encrypt_data(package)
            self.clientSock.send(package)
            time.sleep(self.time_buffer)

            # receiving answer
            data = self.clientSock.recv(1024)
            data = self.decrypt_data(data)

            # printing answer from server
            self.print_log("message from server:")
            print(data)
            self.clientSock.close()

        # authentification token invalid
        else:
            self.print_log("invalid token")
            sys, exit()

    # start client
    def client_start(self):
        try:
            return self.request_connection(self.serverAddr, self.serverPort)
        except KeyboardInterrupt:
            sys.exit('^C')
        except Exception as error:
            self.print_log(error)
            sys.exit()


# help menu
def help_menu():
    print(f"""ultron client
version {client_version}
    uc server instructions:
usage: uc <operands> [INPUT]
    --auth [TOKENFILE]      # verify token validity
    --b [SRC_DIR, DST_DIR]  # backup directory to destination
    --updateuc              # update client to latest version
    --updateuc-devops       # only for developer
    --d -f [FILE]           # download requested file
    --d -r [DIR]            # download requested directory
    --listfs --o [FILE]     # list complete filesystem
    --p                     # ping request
    --r [FILE/DIR]          # remove file or directory from server
    --u [DEST_PATH, FILE]   # upload selected file
    --c                     # encrypt/decrypt stored client data
    --debug                 # enables debug mode

    uc package installer:
usage: uc <operand> [PACKAGE]
    install  # install requested package
    remove   # remove package from host system
    update   # update selected package
    search   # check if requested package is available
    list-all # list all available packages
            """)


# check if directory already exists
def check_dir(dirPath):
    current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if os.path.exists(str(dirPath)):
        pass
    else:
        print(
            f'[{current_date_time}] Directory {dirPath} does not exist --> creating...')
        os.makedirs(dirPath)

# opperand is not supported


def operand_unsupported():
    print('This feature is still under development and currently unavailable.')
    sys.exit()


# read token from file
def recieve_token(tokenfile):
    with open(tokenfile, 'r') as file:
        token = file.read()
    file.close()
    return token


# list for available options
opList = [
    "-h", "--h", "-help", "--h", "--r", "--d", "--p", "--b", "--u", "--updateuc", "--auth", "--listfs",
    '--updateuc-devops', 'install', 'remove', 'search', 'update', 'list-all', "--c", "--debug"
]


# main function
def client_start():
    # config variables
    tokenfile = '/etc/ultron-server/token.txt'
    token = recieve_token(tokenfile)
    # configfile = '/etc/ultron-server/config.csv'
    configfile = '/etc/ultron-server/debug.csv'

    # extract/create server configuration
    serverport = 0
    serveraddr = ''
    if os.path.exists(configfile):
        with open(configfile, 'r') as configFile:
            ultronConfig = configFile.read()
        configFile.close()
        comma = ','
        commaPos = []
        for pos, char in enumerate(ultronConfig):
            if (char == comma):
                commaPos.append(pos)
        serveraddr = str(ultronConfig[commaPos[0] + 1:commaPos[1]])
        serverport = str(ultronConfig[commaPos[1] + 1:commaPos[2]])
    else:
        print("---server configuration---")
        serveraddr = input("enter server address: ")
        serverport = input("enter server port: ")
        check_dir('/etc/ultron-server')
        with open(configfile, 'w') as configFile:
            configFile.write(
                ',' +
                str(serveraddr) +
                ',' +
                str(serverport) +
                ',')
        configFile.close()
        print("configuration written to ", configfile)

    # handling arguments
    # precheck args for debug enabled
    debug = False
    for i in range(len(sys.argv)):
        if (sys.argv[i] == "--debug"):
            debug = True
    debugger = Debug(enabled=debug)

    debugger.debug(f"Creating TCPServer instance.")
    client = TCPClient(serveraddr, int(serverport), debugger)
    sysnumberone = 1
    sysnumbertwo = 2
    sysnumberthree = 3
    if len(sys.argv) == 0:
        help_menu()
    elif sys.argv[sysnumberone] in opList:
        if sys.argv[sysnumberone] == 'remove':
            package = sys.argv[sysnumbertwo]
            client.remove(package)
            sys.exit()
        elif sys.argv[sysnumberone] == 'install':
            package = sys.argv[sysnumbertwo]
            client.check_install(package)

        elif sys.argv[sysnumberone] == 'search':
            try:
                package = sys.argv[sysnumbertwo]
            except Exception:
                sys.exit("ERROR: no package specified for search")

        elif sys.argv[sysnumberone] == 'sync':
            operand_unsupported()

        elif sys.argv[sysnumberone] == 'update':
            operand_unsupported()

        elif sys.argv[sysnumberone] == '--sync':
            operand_unsupported()

        if sys.argv[sysnumberone] in ("-help", "-h", "--help", "--h"):
            help_menu()
            sys.exit()
        if client.client_start():
            if sys.argv[sysnumberone] == "--d":
                downloadType = sys.argv[sysnumbertwo]
                if downloadType in ("-f", "-r"):
                    downloadName = sys.argv[sysnumberthree]
                    if downloadType == "-f":
                        downloadType = 0
                    else:
                        downloadType = 1
                else:
                    help_menu()
                try:
                    client.download_script(downloadType, downloadName, token)
                except KeyboardInterrupt:
                    sys.exit("\r\n^C")
                except Exception as e:
                    sys.exit(f'ERROR: {e}')

            elif sys.argv[sysnumberone] == "--p":
                try:
                    client.ping_request()
                except KeyboardInterrupt:
                    sys.exit("\r\n")

            elif sys.argv[sysnumberone] == "--b":
                backup = sys.argv[sysnumbertwo]
                destDir = sys.argv[sysnumberthree]
                try:
                    client.backup_script(backup, destDir, token)
                except KeyboardInterrupt:
                    sys.exit("\r\n")

            elif sys.argv[sysnumberone] == "--u":
                upload = sys.argv[sysnumbertwo]
                file = sys.argv[sysnumberthree]
                try:
                    client.upload_script(upload, file, token)
                except KeyboardInterrupt:
                    sys.exit("\r\n")

            elif sys.argv[sysnumberone] == "--r":
                removeName = sys.argv[sysnumbertwo]
                try:
                    client.remove_script(removeName, token)
                except KeyboardInterrupt:
                    sys.exit('\r\n')

            elif sys.argv[sysnumberone] == "--updateuc":
                try:
                    client.updateuc()
                except KeyboardInterrupt:
                    sys.exit("\r\n")

            elif sys.argv[sysnumberone] == "--updateuc-devops":
                try:
                    os.system('uc --u /ultron-server/uc /usr/bin/uc ')
                except KeyboardInterrupt:
                    sys.exit("\r\n")

            elif sys.argv[sysnumberone] == "--auth":
                tokenFile = sys.argv[sysnumbertwo]
                with open(tokenFile, "r") as tf:
                    token = tf.read()
                tf.close()
                try:
                    client.test_authtoken(token)
                except KeyboardInterrupt:
                    sys.exit("\r\n")

            elif len(sys.argv) == 4 and sys.argv[sysnumberone] == "--listfs" and sys.argv[sysnumbertwo] == "--o":
                oFile = sys.argv[sysnumberthree]
                try:
                    client.listfs(token, oFile)
                except KeyboardInterrupt:
                    sys.exit("\r\n")

            elif sys.argv[sysnumberone] == "--listfs":
                oFile = "NULL"
                try:
                    client.listfs(token, oFile)
                except KeyboardInterrupt:
                    sys.exit("\r\n")

            elif sys.argv[sysnumberone] == 'install':
                package = sys.argv[sysnumbertwo]
                try:
                    client.install(token, package)
                except KeyboardInterrupt:
                    sys.exit("\r\n")

            elif sys.argv[sysnumberone] == 'list-all':
                try:
                    client.listall(token)
                except KeyboardInterrupt:
                    sys.exit("\r\n")

            elif sys.argv[sysnumberone] == 'remove':
                package = sys.argv[sysnumbertwo]
                try:
                    client.remove(token, package)
                except KeyboardInterrupt:
                    sys.exit("\r\n")
            elif sys.argv[sysnumberone] == "--c":
                try:
                    client.crypt()
                except KeyboardInterrupt:
                    sys.exit("\r\n")

            elif sys.argv[sysnumberone] == 'search':
                try:
                    client.search(token, package)
                except KeyboardInterrupt:
                    sys.exit("\r\n")
    else:
        help_menu()


# start client
if __name__ in "__main__":
    client_start()
