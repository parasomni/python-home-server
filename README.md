# python-home-server » a simple command line home server.

This python-home-server called "ultron-server" is a simple command line server. It can be used as an alternative to NAS or FTP servers. As its completely written in python, it can be easily improved and new features can be added by the user. The server itself handles files between the client and the server. All actions are symmetric encrypted with the primary key generated with the setup script. Available server options are described in the help section of uc.py. Ultron-server has the possibility to serve as a package manager to install important tools the user may needs on any device. The packages will be downloaded and integrated in the system.  

# Setup:

- run the server-setup.py and cleint-setup.py script. It will create the private key for encryption and generates the user token for authentication.

- now you can run the server by executing the command *us* and the client by executing the command *uc* 

- the server script will create an err_log.txt file for errors occurred during runtime
  and a conn_log.txt file for logging incoming connections.

- usi.py is an optional security file. It creates integrities of the files key.txt, token.txt and valid_token.txt.
  Therefore it can be excluded if these files have been compromised.


