   ![ultron server](logo/ultron-server.png)

# python-home-server » a simple command line home server

The Ultron Server is a lightweight command-line server written entirely in Python, designed as an alternative to NAS or FTP servers. Because it is fully implemented in Python, users can easily customize and expand its features. The server manages file transfers between client and server, with all actions symmetrically encrypted using AES-256 and ECDH for the key exchange. Detailed information on available commands is provided in the help section of uc.py. Additionally, Ultron Server can function as a package manager, allowing users to download and integrate essential tools directly onto any device as needed. 

# Setup:

## 1. Clone the repository

    git clone https://github.com/rysecx/python-home-server && cd python-home-server


## 2. Server setup

 To setup the server on a device run the installation wizard:

    sudo python3 installation-wizard.py

  The wizard generates a user token for authentication and adds it to the *valid-tokens.txt* file where all valid users are stored in.

  NOTE: The user token has to be copied to the same directory where the installation-wizard is located if one already exists! Otherwise the wizard generates a new user token.

  You can now start the server:  
  
    sudo us --a [ADDRESS] --p [PORT]

  The server creates a *err_log.txt* file for errors occurred during runtime and a *conn_log.txt* file for logging incoming connections.

You can run Ultron Server as a background daemon using systemd by following these steps:

    sudo mv ultron.service /etc/systemd/system/ultron.service
    sudo systemctl daemon-reload
    sudo systemctl enable ultron.service
    sudo systemctl start ultron.service

  Ensure the daemon is running:
    
    sudo systemctl status ultron.service
  

## 3. Client setup

To setup the client run once again the installation wizard:

    sudo python3 installation-wizard.py

   You can now run the command `uc -h` to see all available options. By running the script for the first time the programm will guide you through the server configuration.

   Run the following command to verify the validity of the authentication token: 
   
    uc --auth /etc/ultron-server/token.txt

## 4. Additional security feature

*usi.py* is a security script that verifies the integrities of *token.txt* and *valid-token.txt*.
 You can use it by the following command:

    sudo python3 usi.py

## 5. Ultron package manager

Ultron package manager can be used to download necessary tools from the server. As an example you can use the provided *packages* folder which has to be copied to the server directory `/ultron-server/packages`


