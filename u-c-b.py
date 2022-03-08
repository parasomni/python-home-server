#!/bin/python3
# version 1.0.4
import socket
import sys
import os
from datetime import datetime
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

class TCPClient:

    def __init__(self, host, port):
        self.serverAddr = host
        self.serverPort = port
        self.token = ''
        self.clientSock = 0

    def print_log(self, msg):
        current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f'[{current_date_time}] {msg}')

    def request_connection(self, serverAddr, serverPort):
        self.print_log(f'creating socket...')
        self.clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.print_log(f'request connection from [{serverAddr}]::[{serverPort}]')
        try:
            self.clientSock.connect((serverAddr, serverPort))
            self.print_log(f'connected succesfully. welcome to ultron!')
            return True
        except Exception as error:
            self.print_log(error)
    
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
    
    def ping_request(self):
        self.print_log(f'requesting ping from [{self.serverAddr}]::[{self.serverPort}]')
        self.clientSock.send(cOP.ping.encode())
        answ = self.clientSock.recv(1024)
        ping = answ.decode()
        if ping == cOP.OK:
            self.print_log('server is online')
            self.clientSock.close()
            sys.exit
        else:
            self.print_log('connection refused')
            self.clientSock.close()
    
    def download_script(self, fileName, clientToken):
        self.print_log(f'requesting file from [{self.serverAddr}]::[{self.serverPort}]')
        self.clientSock.send(cOP.download.encode())
        time.sleep(0.5)
        clientToken = clientToken.encode()
        clientToken = self.encrypt_data(clientToken)
        self.clientSock.send(clientToken)
        resp = self.clientSock.recv(1024)
        resp = resp.decode()
        if resp == cOP.OK:
            fileNameEncr = fileName.encode()
            fileNameEncr = self.encrypt_data(fileNameEncr)
            self.clientSock.send(fileNameEncr)
            resp = self.clientSock.recv(1024)
            resp = resp.decode()
            if resp == cOP.OK:
                filesize = self.clientSock.recv(1024)
                filesize = self.decrypt_data(filesize)
                filesize = filesize.decode()
                filesize = int(filesize)
                fileData = ''
                fragmentCount = 0
                if filesize > 1448:
                    fragmentCount = filesize / 1448
                    fragmentCount += 1
                else:
                    fragmentCount = 1
                for i in range(int(fragmentCount)):
                    fileBytes = self.clientSock.recv(1500)
                    fileBytes = fileBytes.decode()
                    fileData += fileBytes
                    if int(filesize) == int(len(fileData)):
                        i = int(fragmentCount)
                        break 
                    else:
                        pass
                fileData = fileData.encode()
                fileData = self.decrypt_data(fileData)
                download = 'downloads/' + fileName
                with open(download, 'wb') as file:
                    file.write(fileData)
                file.close()
                self.print_log(f'file written to {download}. closing connection')
                self.clientSock.send(cOP.OK.encode())
                self.clientSock.close()
            elif resp == cOP.rst:
                self.print_log(f'file_not_found_error: closing connection to [{self.serverAddr}]::[{self.serverPort}]')
                self.clientSock.close()
        elif resp == cOP.forbidden:
            self.print_log('403 forbidden: invalid token')
            self.clientSock.close()
        else:
            self.print_log('could not resolve response from server. quitting')
            self.clientSock.close()

    
    def listfs(self, clientToken, oFile):
        self.print_log(f'requesting listfs from [{self.serverAddr}]::[{self.serverPort}]')
        self.clientSock.send(cOP.listfs.encode())
        time.sleep(0.2)
        clientToken = str(clientToken).encode()
        clientToken = self.encrypt_data(clientToken)
        self.clientSock.send(clientToken)
        answ = self.clientSock.recv(1024)
        answ = answ.decode()
        if answ == cOP.rst:
            self.print_log(f'connection refused by [{self.serverAddr}]::[{self.serverPort}]')
            self.clientSock.close()
        elif answ == cOP.OK:
            fragmentCount = 0
            filesize = self.clientSock.recv(1024)
            filesize = self.decrypt_data(filesize)
            filesize = filesize.decode()
            filesize = int(filesize)
            fileData = ''
            if filesize > 1448:
                fragmentCount = filesize / 1448
                fragmentCount += 1
            else:
                fragmentCount = 1
            for i in range(int(fragmentCount)):
                fileBytes = self.clientSock.recv(1500)
                fileBytes = fileBytes.decode()
                fileData += fileBytes
            fileData = fileData.encode()
            fileData = self.decrypt_data(fileData)
            fileData = fileData.decode()
            if oFile == "NULL":
                self.print_log('recieved filesystem:\r\n')
                print(fileData)
            else:
                with open(oFile, 'w') as file:
                    file.write(fileData)
                file.close()
                self.print_log(f'filesystem written to {oFile}')
            self.clientSock.send(cOP.OK.encode())
            self.clientSock.close()
    
    def test_authtoken(self, clientToken): 
        self.print_log(f'requesting token integrity from [{self.serverAddr}]::[{self.serverPort}]')
        self.clientSock.send(cOP.usertoken.encode())
        clientToken = str(clientToken).encode()
        clientToken = self.encrypt_data(clientToken)
        self.clientSock.send(clientToken)
        integrity = self.clientSock.recv(1024)
        integrity = integrity.decode()
        if integrity == cOP.OK:
            self.print_log('auth_token valid')
            self.clientSock.close()
        elif integrity == cOP.rst:
            self.print_log('auth_token invalid. Please contact the administrator for a new token')
            self.clientSock.close()
        else:
            self.print_log('could not answer request. closing connection')
            self.clientSock.close()
     
    def updatedb(self):
        self.print_log(f'updating db from [{self.serverAddr}]::[{self.serverPort}]')
        self.clientSock.send(cOP.serverupdate.encode())
        filesize = self.clientSock.recv(1024)
        filesize = self.decrypt_data(filesize)
        filesize = filesize.decode()
        filesize = int(filesize)
        fileData = ''
        fragmentCount = 0
        if filesize > 2048:
            fragmentCount = (filesize + 4096) / 1500
        else: 
            fragmentCount = 1
        for i in range(int(fragmentCount)):
            fileBytes = self.clientSock.recv(2048)
            fileBytes = fileBytes.decode()
            fileData += fileBytes
        fileData = fileData.encode()
        fileData = self.decrypt_data(fileData)
        fileData = fileData.decode()
        with open('UCB.py', 'w') as file:
            file.write(fileData)
        file.close()
        if os.path.getsize('UCB.py') == int(filesize):
            self.print_log('updated successfully')
        else:
            self.print_log('ERROR. update failed!')
        self.clientSock.close()    

    def upload_script(self, fileDirectory, userFile, userToken):
        self.print_log(f'requesting file transfer from [{self.serverAddr}]::[{self.serverPort}]')
        self.clientSock.send(cOP.upload.encode())
        time.sleep(0.2)
        userToken = str(userToken).encode()
        userToken = self.encrypt_data(userToken)
        self.clientSock.send(userToken)
        answ = self.clientSock.recv(1024)
        answ = answ.decode()
        if answ == cOP.OK:
            self.print_log('sending file...')
            # sending fileDirectory
            time.sleep(0.2)
            fileDirectory = str(fileDirectory).encode()
            fileDirectory = self.encrypt_data(fileDirectory)
            self.clientSock.send(fileDirectory)
            # self.print_log('fileDirectory sent')
            with open(userFile, 'rb') as file:
                data = file.read()
            file.close()
            data = self.encrypt_data(data)
            # sending filesize
            # self.print_log('filesize sent')
            fileSize = len(data)
            fileSize = str(fileSize).encode()
            fileSize = self.encrypt_data(fileSize)
            self.clientSock.send(fileSize)
            time.sleep(0.2)
            #self.print_log('sending file...')
            self.clientSock.send(data)
            self.print_log('file sent. waiting for OK from server')
            answ = self.clientSock.recv(1024)
            if answ.decode() == cOP.OK:
                self.print_log('file sending complete')
                self.clientSock.close()
            elif answ.decode() == cOP.rst:
                self.print_log('file sending failed')
            else:
                self.print_log('could not resolve answer from server. quitting')
                self.clientSock.close()
        elif answ == cOP.rst: 
            self.print_log('permission denied: token_invalid')
            self.clientSock.close()
        else:
            self.print_log('could not resolve answer from server. quitting')
            self.clientSock.close()
        
    def backup_script(self, srcDirectory, dstDirectory, clientToken):
        # inportet functions
        def get_size(dir1):
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(dir1):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    # skip if it is symbolic link
                    if not os.path.islink(fp):
                        total_size += os.path.getsize(fp)
            return total_size
        
        def print_process(sentBytes):
            current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            dirSize = get_size(srcDirectory)
            currSize = sentBytes / dirSize * 100
            currSize = '{:.2f}'.format(currSize)
            print(f'[{current_date_time}]', 'sending files (', currSize,'%)', end='\r')
        
        def send_backup():
            sentBytes = 0
            self.print_log(f'requesting file transfer from [{self.serverAddr}]::[{self.serverPort}]')
            self.clientSock.send(cOP.backup.encode())
            time.sleep(0.2)
            userToken = str(clientToken).encode()
            userToken = self.encrypt_data(userToken)
            self.clientSock.send(userToken)
            answ = self.clientSock.recv(1024)
            answ = answ.decode()
            if answ == cOP.OK:
                self.print_log('preparing backup...')
                self.print_log('DO NOT TURN OFF YOUR DEVICE!')
                # sending dstDirectory to server
                # self.print_log(f'sending dstDirectory {dstDirectory}')
                dstDirEncr = str(dstDirectory).encode()
                dstDirEncr = self.encrypt_data(dstDirEncr)
                self.clientSock.send(dstDirEncr)
                time.sleep(0.2)
                # checking directory
                if os.path.exists(str(srcDirectory)):
                    pass
                else:
                    self.print_log(f'ERROR: could not locate {srcDirectory}')
                    self.clientSock.close()
                    sys.exit()
                # sending backupsize 
                # self.print_log('sending backupsize')
                backupSize = get_size(srcDirectory)
                backupSize = str(backupSize).encode()
                backupSize = self.encrypt_data(backupSize)
                self.clientSock.send(backupSize)
                time.sleep(0.2)
                # fetching files and dirnames from srcDirectory and sending them to server
                cut = len(srcDirectory)
                for dirpath, dirnames, files in os.walk(srcDirectory):
                    # sending status
                    # self.print_log('sending transferStatus')
                    time.sleep(0.2)
                    self.clientSock.send(cOP.backup.encode())
                    # sending directory name
                    dirpath = dirpath + '/'
                    # self.print_log(f'sending fileDirectoryName {dirpath}')
                    dirpathEncr = str(dirpath).encode()
                    dirpathEncr = self.encrypt_data(dirpathEncr)
                    self.clientSock.send(dirpathEncr)
                    time.sleep(0.2)
                    for fileName in files:
                        # sending fileOperand
                        # self.print_log('sending fileOperand')
                        time.sleep(0.2)
                        self.clientSock.send(cOP.file.encode())
                        # sending fileName
                        # self.print_log(f'sending fileName {fileName}')
                        fileNameEncr = str(fileName).encode()
                        fileNameEncr = self.encrypt_data(fileNameEncr)
                        time.sleep(0.2)
                        self.clientSock.send(fileNameEncr)
                        with open(dirpath + fileName, 'rb') as fileOpen:
                            fileBytes = fileOpen.read()
                        fileOpen.close()
                        # sending fileSize
                        # self.print_log('sending filesize')
                        fileSize = len(fileBytes)
                        fileSize = str(fileSize).encode()
                        fileSize = self.encrypt_data(fileSize)
                        time.sleep(0.2)
                        self.clientSock.send(fileSize)
                        time.sleep(0.2)
                        # printing process
                        sentBytes += len(fileBytes)
                        print_process(sentBytes)
                        # sending bytes
                        # self.print_log('sending filebytes')
                        fileBytes = self.encrypt_data(fileBytes)
                        # sending encr bytes size 
                        # self.print_log('sending filesize')
                        fileBytesSize = len(fileBytes)
                        fileBytesSize = str(fileBytesSize).encode()
                        fileBytesSize = self.encrypt_data(fileBytesSize)
                        self.clientSock.send(fileBytesSize)
                        time.sleep(0.2)
                        self.clientSock.send(fileBytes)
                        time.sleep(0.3)
                        # waiting for OK from server
                        # self.print_log('waiting for server status...')
                        status = self.clientSock.recv(1024)
                        status = status.decode()
                        # self.print_log('recieved server status')
                        if status == cOP.OK:
                            # self.print_log('file sending complete')
                            pass
                        else:
                            self.print_log(f'message from server: {status}')
                # sending status complete
                # self.print_log('file sending to server complete. waiting for endCheck response')
                self.clientSock.send(cOP.OK.encode())
                time.sleep(0.2)
                endCheck = self.clientSock.recv(1024)
                endCheck = endCheck.decode()
                if endCheck == cOP.OK:
                    self.print_log('backup completed. quitting')
                    self.clientSock.close()
                else:
                    self.print_log(f'message from server: {endCheck}')
                    self.clientSock.close()
            elif answ == cOP.rst():
                self.print_log('connection refused')
                self.clientSock.close()
            else:
                self.print_log('could not resolve response. QUITTING')
                self.clientSock.close()
        try: 
            send_backup()
        except Exception as e:
            print(e)

    def client_start(self):
        try: 
            return self.request_connection(self.serverAddr, self.serverPort)
        except KeyboardInterrupt:
            sys.exit('^C')
        except Exception as error:
            self.print_log(error)
            sys.exit()

def help_menu():
        print("""
usage: ./UCB.py [SERVER_ADDRESS] [SERVER_PORT] <operands> [INPUT]
    upload: --u [DEST_PATH, UPLOAD_FILE, TOKEN_FILE]
    download: --d [DOWNLOAD_FILE, TOKEN_FILE]
    chatroom: --c [USERNAME, ROOMTOKEN]
    ping: --p
    clientupdate: --updatedb
    sync: --sync [TOKEN_FILE]
    authentication: --auth [TOKEN_FILE] (required when using --u, --d, --b, --sync, --listfs)
    list filesystem: --listfs [TOKEN_FILE] (optional output: --o [FILE])
    backup: --b [INPUT_DIRECTORY, DESTINATION_DIRECTORY, TOKEN_FILE]
            """)

def operand_unsupported():
    print('Sorry. This feature is still in development and currently unavailable.')
    sys.exit()

def client_start():
    if len(sys.argv) == 1:
            help_menu()
    elif sys.argv[3] in ("-h", "--h", "-help", "--h", "--d", "--p", "--b", "--u", "--updatedb", "--auth", "--listfs"):
        server = sys.argv[1]
        port = sys.argv[2]
        client = TCPClient(server, int(port))
        if client.client_start():
            if sys.argv[3] in ("-help", "-h", "--help", "--h"):
                client.help_menu()
            elif sys.argv[3] == "--d":
                download = sys.argv[4]
                tokenFile = sys.argv[5]
                with open(tokenFile, 'r') as file:
                    token = file.read()
                file.close()
                try:
                    client.download_script(download, token)
                except KeyboardInterrupt:
                    sys.exit("\r\n^C")
            elif sys.argv[3] == "--p":
                try:
                    client.ping_request()
                except KeyboardInterrupt:
                    sys.exit("\r\n")
            elif sys.argv[3] == "--b":
                backup = sys.argv[4]
                # backup = backup + '/'
                destDir = sys.argv[5] 
                # destDir = destDir + '/'
                token = sys.argv[6]
                with open(token, 'rb') as file:
                    token = file.read()
                file.close()
                try:
                    client.backup_script(backup, destDir, token)
                except KeyboardInterrupt:
                    sys.exit("\r\n")

            elif sys.argv[3] == "--u":
                upload = sys.argv[4]
                file = sys.argv[5]
                token = sys.argv[6]
                with open (token, 'r') as tf:
                    token = tf.read()
                tf.close()
                try:
                    client.upload_script(upload, file, token)
                except KeyboardInterrupt:
                    sys.exit("\r\n")
            
            elif sys.argv[3] == "--c":
                username = sys.argv[4]
                token = sys.argv[5]
                operand_unsupported()
                try:
                    client.chatroom_script(username, token)
                except KeyboardInterrupt:
                    sys.exit("\r\n")
            
            elif sys.argv[3] == "--updatedb":
                try:
                    client.updatedb()
                except KeyboardInterrupt:
                    sys.exit("\r\n")
            elif sys.argv[3] == "--sync":
                operand_unsupported
                try:
                    client.sync_script()
                except KeyboardInterrupt:
                    sys.exit("\r\n")
            elif sys.argv[3] == "--auth":
                tokenFile = sys.argv[4] 
                with open(tokenFile, "r") as tf:
                    token = tf.read()
                tf.close()
                try:
                    client.test_authtoken(token)
                except KeyboardInterrupt:
                    sys.exit("\r\n")
            elif len(sys.argv) == 7 and sys.argv[3] == "--listfs" and sys.argv[5] == "--o":
                oFile = sys.argv[6]
                tokenFile = sys.argv[4] 
                with open(tokenFile, "r") as tf:
                    token = tf.read()
                tf.close()
                try:
                    client.listfs(token, oFile)
                except KeyboardInterrupt:
                    sys.exit("\r\n")

            elif sys.argv[3] == "--listfs":
                tokenFile = sys.argv[4] 
                oFile = "NULL"
                with open(tokenFile, "r") as tf:
                    token = tf.read()
                tf.close()
                try:
                    client.listfs(token, oFile)
                except KeyboardInterrupt:
                    sys.exit("\r\n")

    elif sys.argv[3] in ('--sync', '--c'):
        operand_unsupported()
    
    else:
        help_menu()


try:
    client_start()
except Exception as error:
    print('ERROR: ', str(error))
    sys.exit()
