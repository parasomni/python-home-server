# python-home-server » a simple command line home server

This python-home-server called "ultron-server" is a simple command line server. It can be used as an alternative to NAS or FTP servers. As its completely written in python, it can be easily improved and new features can be added by the user. The server itself handles files between the client and the server. All actions are symmetric encrypted with the primary key generated by the setup script. Available server options are described in the help section of uc.py. Ultron-server has the possibility to serve as a package manager to install important tools the user may needs on any device. The packages will be downloaded and integrated in the system.  

# Setup:

## 1. Download necessary files

At first fetch the files from the python-home-server repository:

`git clone https://github.com/rysecx/python-home-server && cd python-home-server`


## 2. Server setup

 To setup the server on the device you want to install it run the following code:

`python3 server-setup.py` 

  This script generates the private key for the encryption and a user token for authentification. The generated user token is added to the *valid-tokens.txt* file where all valid users are stored in.

  NOTE: The encryption key and user token have to be copied in the same directory where the client-setup.py script is located! Otherwise the script will generate a new encryption key and user token.

  You can now start the server: `us --a address --p port`

  The server script will create an *err_log.txt* file for errors occurred during runtime and a *conn_log.txt* file for logging incoming connections.
  

## 3. Client setup

To setup the client on a device you want to install it run the following code:

`python3 client-setup.py`

   You can now run the command `us -h` to see all available options. By running the script for the first time the programm will guide you through the server configuration.

   Run the following command to check if the authentification token is valid: `us --auth /etc/ultron-server/token.txt`

## 4. Additional security feature

*usi.py* is an optional security file. It creates integrities of the files *key.txt*, *token.txt* and *valid-token.txt*. Therefore it can be excluded if these files have been compromised. You can setup it by the command:

`python3 usi.py`


