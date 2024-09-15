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

# Function to recursively decrypt files
decrypt_directory() {
    local dir=$1
    for file in "$dir"/*.enc; do
        if [ -f "$file" ]; then
            echo "Decrypting file: $file"
            decrypted_file="${file%.enc}"  # Remove the .enc extension
            openssl enc -d -aes-256-cbc -pbkdf2 -in "$file" -out "$decrypted_file" -pass file:"$PASSWORD_FILE"
            if [ $? -ne 0 ]; then
                echo "Error decrypting $file"
            else
                rm $file
                echo "Successfully decrypted $file to $decrypted_file"
            fi
        fi
    done

    # Recursively handle subdirectories
    for subdir in "$dir"/*; do
        if [ -d "$subdir" ]; then
            decrypt_directory "$subdir"
        fi
    done
}

# Start the decryption process
decrypt_directory "$DIRECTORY"

