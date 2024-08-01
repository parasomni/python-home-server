#!/bin/bash

#!/bin/bash

DIRECTORY=$(cat /etc/ultron-server/crypt_directory.txt)
PASSWORD_FILE="/etc/ultron-server/crypt_password.txt"

# Ensure the directory exists
if [ ! -d "$DIRECTORY" ]; then
    echo "Directory $DIRECTORY does not exist."
    exit 1
fi

# Ensure the password file exists
if [ ! -f "$PASSWORD_FILE" ]; then
    echo "Password file $PASSWORD_FILE does not exist."
    exit 1
fi

# Function to recursively encrypt files
encrypt_directory() {
    local dir=$1
    for file in "$dir"/*; do
        if [ -f "$file" ]; then
            echo "Encrypting file: $file"
            openssl enc -aes-256-cbc -salt -pbkdf2 -in "$file" -out "$file.enc" -pass file:"$PASSWORD_FILE"
            if [ $? -ne 0 ]; then
                echo "Error encrypting $file"
            else
                rm $file
                echo "Successfully encrypted $file to $file.enc"
            fi
        elif [ -d "$file" ]; then
            encrypt_directory "$file"  # Recursively call the function for subdirectories
        else
            echo "$file is not a regular file or directory, skipping."
        fi
    done
}

# Start the encryption process
encrypt_directory "$DIRECTORY"


