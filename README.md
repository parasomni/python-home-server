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

- run the server-setup.py script. It will create the private key for encryption and generates the user token for authentication.

- now you can run the server by executing the command *us*

- the server script will create an err_log.txt file for errors occurred during runtime
  and a conn_log.txt file for logging incoming connections.

- usi.py is an optional security file. It creates integrities of the files err_log.txt, key.txt, token.txt and valid_token.txt.
  Therefore it can be excluded that these files got manipulated.
  You only need to setup the Array again in line 46.

Enjoy!
