# python-home-server
A simple command line home server. Upgradeable and improveable.

This python-home-server is a command-line server. It has no GUI 
and only a few options available. It can backup files and folders. Also it
supports to download a file. It can make a list-file of the complete filesystem 
to search different patterns for example with the grep tool. It allows up to 10
multiple connections but can be upgraded by the user itself. Until yet only four 
different users are supported but can be manually upgraded.
In the following it is descriped how to setup the server.

Setup:

- at first we have to create three files called 'key.txt', 'token.txt' and
  'valid_token.txt' by running the setup.py script.
  the key file is very important because it includes the private key for the 
  encryption. token.txt stores the user token which is neccessary to authenticate 
  to the server. valid_token.txt is a collection of valid tokens allowed to access the server.
  All user tokens must be stored in valid_tokens.txt

- next step is to setup the directories for the users. In line 263 of u-s-b.py 
  you will find an array with four empty values ["","","",""]. In it you can 
  define the user directories.

- now the setup is allready done. Copy the files u-s-b.py, key.txt and valid_token.txt
  in the same directory. The client script u-c-b.py needs key.txt and token.txt
  in the same directory. 

- how to run python files is described at the beginning

- the server script will create an err_log.txt file for errors occurred during runtime
  and a conn_log.txt file for logging incoming connections.

- usi.py is an optional security file. It creates integrities of the files err_log.txt, key.txt, token.txt and valid_token.txt.
  Therefore it can be excluded that these files got manipulated.
  You only need to setup the Array again in line 46.

Enjoy!
