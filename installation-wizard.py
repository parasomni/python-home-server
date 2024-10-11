#!/usr/bin/python3

import tkinter as tk
import sys
import random
import os
import shutil
import time
import threading

from tkinter.filedialog import askopenfilename
from tkinter import scrolledtext
from cryptography.fernet import Fernet

os.system("chown root:root installation-wizard.py")

def token_gen():
    upperCase = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
                     "U", "V", "W", "X", "Y", "Z"]
    lowerCase = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
                     "u", "v", "w", "x", "y", "z"]
    nNumbers = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    specialChars = ["\"", "{", "}", ".", ",", ";", "/", "\\", "<", ">", "=", "[", "]", "^", "~", "_",
                        "|", "%", "&", "'", "`", "@", "*", "-", "#", "+", "$", "!", ":", "?"]
    token = ""
    for i in range(30):
        r1 = random.randint(1, 4)
        if r1 == 1:
            r2 = random.randint(0, 25)
            token += upperCase[r2]
        elif r1 == 2:
            r2 = random.randint(0, 25)
            token += lowerCase[r2]
        elif r1 == 3:
            r2 = random.randint(0, 9)
            token += nNumbers[r2]
        elif r1 == 4:
            r2 = random.randint(0, 28)
            token += specialChars[r2]
        else:
            print("Error: could not generate session_token")
            sys.exit("\r\n")
    return token

token_path = os.getcwd() + '/token.txt'
ultron_path = '/etc/ultron-server/'
server_file = 'us-v1.1.8-stable.py'
client_file = 'uc-v1.1.8-stable.py'
valid_tokens = '/etc/ultron-server/valid-tokens.txt'
token = ''

def check_dir(dirPath):
    if os.path.exists(str(dirPath)):
        pass
    else:
        os.makedirs(dirPath)

def install_server():
    global cred_file
    global client1
    global client2
    global client3 
    global client4
    global alert_email
    global trash_email
    global time_delay
    global max_number_conn_ddos
    check_dir(ultron_path)

    def complete_setup():
        def update_text(status):
            text_output.config(state=tk.NORMAL)
            text_output.insert(tk.END, status + '\n')
            text_output.config(state=tk.DISABLED)
            text_output.update()

        def server_setup():
            if os.path.exists(token_path):
                update_text(f"token found: moving {token_path} to {ultron_path}token.txt")
                os.system(f'mv {token_path} {ultron_path}token.txt')
                with open(f'{ultron_path}token.txt', 'r') as f:
                    token = f.read()
                with open(valid_tokens, 'a') as f:
                    f.write(str(token))
                f.close()
                update_text(f'updated file {valid_tokens}')
            elif os.path.exists(ultron_path + 'token.txt'):
                update_text(f"token found: {ultron_path}token.txt")
                with open(f'{ultron_path}token.txt', 'r') as f:
                    token = f.read()
                with open(valid_tokens, 'a') as f:
                    f.write(str(token))
                f.close()
                update_text(f'updated file {valid_tokens}')
            else:
                update_text(f"no token found. skipping.")
                pass
            update_text(f'setting time delay to {time_delay}s')
            config = f"""
            ### server configuration ###

            ## client assets
            # Indicates the client paths
                    ,{client1},
                    ,{client2},
                    ,{client3},
                    ,{client3},


            ## server assets       
            # Indicates the vaild token file path
                    ,/etc/ultron-server/valid-tokens.txt,

            # Server time delay
                    ,{time_delay},


            ## Denial of Service protection
            # maximum number of connections within 10 seconds to initialize server shutdown 
                    ,{max_number_conn_ddos},

            # Email address which should report upcoming alerts
                    ,{trash_email},

            # Email address to which upcoming alerts should be reported
                    ,{alert_email},

            # Credential file which includes login password of report email
                    ,{cred_file},

            """
            with open (ultron_path + 'server.cfg', 'w') as f:
                f.write(config)
            f.close()
            update_text("writing configuration...")
            update_text(config)
            update_text('setting up triggers')
            try:
                os.system(f'mv {server_file} /usr/bin/us')
                os.system('chmod +x /usr/bin/us')
                update_text("successfully installed ultron-server!")
            except Exception as e:
                update_text(e)

        client1 = ent_client1.get()
        client2 = ent_client2.get()
        client3 = ent_client3.get()
        client4 = ent_client4.get()
        time_delay = ent_time_delay.get()
        max_number_conn_ddos = ent_max_ddos.get()
        alert_email = ent_alert_email.get()
        trash_email = ent_trash_email.get()
        cred_file = txt_edit.get("1.0", tk.END)

        def exit_program():
            root.destroy()
            sys.exit()

        root = tk.Tk()
        root.title("Server setup")

        text_output = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=20, state=tk.DISABLED)
        text_output.grid(row=0, column=0, columnspan=2)

        start_button = tk.Button(root, text="Install", command=lambda: threading.Thread(target=server_setup).start())
        start_button.grid(row=1, column=0, sticky=tk.W)

        exit_button = tk.Button(root, text="Exit", command=exit_program)
        exit_button.grid(row=1, column=1, sticky=tk.E)

        root.mainloop()

    def fetch_file():
        filepath = askopenfilename(
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not filepath:
            return
        txt_edit.delete("1.0", tk.END)
        txt_edit.insert(tk.END, filepath)

    root = tk.Tk()
    root.title("Server setup")
    root.resizable(width=False, height=False)

    # general information
    lbl_info = tk.Label(root, text="Please fill in the gaps with the required information.")
    lbl_info.grid(row=0, column=0, sticky=tk.N)

    # Client setup
    frm_clients = tk.Frame(root, bd=5)
    frm_clients.grid(row=1, column=0, sticky=tk.W)
    lbl_clients = tk.Label(frm_clients, text="Please specify the filesystem paths each client has access to:", fg="orange")
    lbl_clients.grid(row=1, column=0, sticky=tk.W)
    lbl_clients.grid(row=1, column=0, sticky=tk.W)
    lbl_client1 = tk.Label(frm_clients, text="Client 1: ")
    lbl_client1.grid(row=2, column=0, sticky=tk.E)
    ent_client1 = tk.Entry(frm_clients, width=50)
    ent_client1.grid(row=2, column=1, sticky=tk.W)
    lbl_client2 = tk.Label(frm_clients, text="Client 2: ")
    lbl_client2.grid(row=3, column=0, sticky=tk.E)
    ent_client2 = tk.Entry(frm_clients, width=50)
    ent_client2.grid(row=3, column=1, sticky=tk.W)
    lbl_client3 = tk.Label(frm_clients, text="Client 3: ")
    lbl_client3.grid(row=4, column=0, sticky=tk.E)
    ent_client3 = tk.Entry(frm_clients, width=50)
    ent_client3.grid(row=4, column=1, sticky=tk.W)
    lbl_client4 = tk.Label(frm_clients, text="Client 4: ")
    lbl_client4.grid(row=5, column=0, sticky=tk.E)
    ent_client4 = tk.Entry(frm_clients, width=50)
    ent_client4.grid(row=5, column=1, sticky=tk.W)

    # server time delay setup
    frm_td = tk.Frame(root, bd=1)
    frm_td.grid(row=6, column=0, sticky=tk.W)    
    lbl_td = tk.Label(frm_td, text=" Server time delay setup: ", fg="orange")
    lbl_td.grid(row=6, column=0, sticky=tk.W)
    ent_time_delay = tk.Entry(frm_td, width=20)
    ent_time_delay.grid(row=7, column=1, sticky=tk.N)
    lbl_time_delay = tk.Label(frm_td, text=" Please enter the server time delay in seconds: ")
    lbl_time_delay.grid(row=7, column=0, sticky=tk.N)

    # DoS setup
    frm_dos = tk.Frame(root, bd=4)
    frm_dos.grid(row=8, column=0, sticky=tk.W)
    lbl_dos = tk.Label(frm_dos, text="Denial of Service protection setup: ", fg="orange")
    lbl_dos.grid(row=8, column=0, sticky=tk.W)
    ent_max_ddos = tk.Entry (frm_dos, width=15)
    ent_max_ddos.grid(row=9, column=1, sticky=tk.W)
    ent_alert_email = tk.Entry(frm_dos, width=50)
    ent_alert_email.grid(row=10, column=1, sticky=tk.E)
    ent_trash_email = tk.Entry(frm_dos, width= 50)
    ent_trash_email.grid(row=11, column=1, sticky=tk.E)
    lbl_max_ddos = tk.Label(frm_dos, text="Please enter the maximum number of connections within 10s to initialize server shutdown: ")
    lbl_max_ddos.grid(row=9, column=0, sticky=tk.W)
    lbl_alert_email = tk.Label(frm_dos, text="Please enter the email address to which upcoming alerts should be reported: ")
    lbl_alert_email.grid(row=10, column=0, sticky=tk.W)
    lbl_trash_email = tk.Label(frm_dos, text="Please enter the email address which should report upcoming alerts: ")
    lbl_trash_email.grid(row=11, column=0, sticky=tk.W)

    # credential file
    txt_edit = tk.Text(frm_dos, width=50, height=1)
    txt_edit.grid(row=12, column=1, sticky="")
    lbl_credit_file = tk.Label(frm_dos, text="Please select the credential file with the login password of your report email address: ")
    lbl_credit_file.grid(row=12, column=0, sticky=tk.W)
    btn_fetch_file = tk.Button(frm_dos, relief=tk.RAISED, text=".", command=fetch_file)
    btn_fetch_file.grid(row=12, column=2, sticky="ew", padx=5, pady=5)

    # Main buttons
    frm_buttons = tk.Frame(root, relief=tk.RAISED, bd=2)
    btn_submit = tk.Button(frm_buttons, text="Submit", command=complete_setup)
    btn_submit.grid(row=13, column=2, sticky=tk.E, padx=230, pady=5)
    btn_exit = tk.Button(frm_buttons, text="Exit", command=root.destroy)
    btn_exit.grid(row=13, column=0, sticky=tk.W, padx=200, pady=5)
    frm_buttons.grid(row=13, column=0, sticky="ewn")
    root.mainloop()

def install_client():
    check_dir(ultron_path)
    def update_text(status):
        text_output.config(state=tk.NORMAL)
        text_output.insert(tk.END, status + '\n')
        text_output.config(state=tk.DISABLED)
        text_output.update()

    def client_setup():
        if os.path.exists(token_path):
            try:
                os.system(f'mv {token_path} {ultron_path}token.txt')
                update_text(f"moving {token_path} to {ultron_path}token.txt")
            except Exception as e:
                update_text(e)
        else:
            token = token_gen()
            update_text("user token generated")
            with open('token.txt', 'wb') as file:
                file.write(token.encode())
            update_text(f'user-token written to {ultron_path}token.txt')

        update_text('setting up triggers')
        try:
            os.system(f'mv {client_file} /usr/bin/uc')
            os.system('chmod +x /usr/bin/uc')
            update_text("successfully installed ultron-client!")
        except Exception as e:
            update_text(e)

    def exit_program():
        root.destroy()
        sys.exit()

    root = tk.Tk()
    root.title("Client setup")
    text_output = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=15, state=tk.DISABLED)
    text_output.grid(row=0, column=0, columnspan=2)
    start_button = tk.Button(root, text="Install", command=lambda: threading.Thread(target=client_setup).start())
    start_button.grid(row=1, column=0, sticky=tk.W)
    exit_button = tk.Button(root, text="Exit", command=exit_program)
    exit_button.grid(row=1, column=1, sticky=tk.E)
    root.mainloop()

def install_guide():
    info="""Please choose the service you wish to install on your system."""
    window = tk.Tk()
    window.title("Installation of ultron-server components")
    window.resizable(width=False, height=False)
    window.rowconfigure(0, minsize=150, weight=1)
    window.columnconfigure(1, minsize=0, weight=1)
    label = tk.Label(window, text=info)
    frm_buttons = tk.Frame(window, relief=tk.RAISED, bd=2)
    btn_install = tk.Button(frm_buttons, text="Install ultron-client", command=install_client)
    btn_uninstall = tk.Button(frm_buttons, text="Install ultron-server", command=install_server)
    btn_install.grid(row=0, column=0, sticky="e", padx=32, pady=5)
    btn_uninstall.grid(row=0, column=1, sticky="w", padx=32, pady=5)
    frm_buttons.grid(row=1, column=0, sticky="ews")
    label.grid(row=0, column=0, sticky="nsew")
    window.mainloop()

def uninstall_ultron():
    shutil.rmtree("/etc/ultron-server")
    try:
        os.remove("/usr/bin/uc")
    except:
        pass
    try:
        os.remove("/usr/bin/us")
    except:
        pass
    status = "Successfully uninstalled all ultron-server components"
    window = tk.Tk()
    window.title("Status")
    window.resizable(width=False, height=False)
    window.rowconfigure(0, minsize=150, weight=1)
    window.columnconfigure(1, minsize=0, weight=1)
    label = tk.Label(window, text=status, fg="green")
    frm_buttons = tk.Frame(window, relief=tk.RAISED, bd=2)
    btn_abort = tk.Button(frm_buttons, text="Exit", command=window.destroy)
    btn_abort.grid(row=0, column=0, sticky="e", padx=150, pady=5)
    frm_buttons.grid(row=1, column=0, sticky="ews")
    label.grid(row=0, column=0, sticky="nsew")
    window.mainloop()

def uninstall_guide():
    if os.path.exists("/etc/ultron-server"):
        info = """
This action will uninstall all components from your system.
Please be aware that there is no possibility to restore any files after proceeding with the uninstallation.
        """
        window = tk.Tk()
        window.title("Uninstallation of ultron-server components")
        window.resizable(width=False, height=False)
        window.rowconfigure(0, minsize=150, weight=1)
        window.columnconfigure(1, minsize=0, weight=1)
        label = tk.Label(window, text=info, fg="red")
        frm_buttons = tk.Frame(window, relief=tk.RAISED, bd=2)
        btn_uninstall = tk.Button(frm_buttons, text="Uninstall all components", bg="red", command=uninstall_ultron)
        btn_abort = tk.Button(frm_buttons, text="Abort", command=window.destroy)
        btn_abort.grid(row=0, column=0, sticky="e", padx=100, pady=5)
        btn_uninstall.grid(row=0, column=1, sticky="w", padx=50, pady=5)
        frm_buttons.grid(row=1, column=0, sticky="ews")
        label.grid(row=0, column=0, sticky="nsew")
        window.mainloop()
    else:
        info = "No existing installation of ultron-server components found."
        window = tk.Tk()
        window.title("Uninstallation of ultron-server components")
        window.resizable(width=False, height=False)
        window.rowconfigure(0, minsize=150, weight=1)
        window.columnconfigure(1, minsize=0, weight=1)
        label = tk.Label(window, text=info, fg="red")
        frm_buttons = tk.Frame(window, relief=tk.RAISED, bd=2)
        btn_abort = tk.Button(frm_buttons, text="Exit", command=window.destroy)
        btn_abort.grid(row=0, column=0, sticky="e", padx=200, pady=5)
        frm_buttons.grid(row=1, column=0, sticky="ews")
        label.grid(row=0, column=0, sticky="nsew")
        window.mainloop()

def start_wizard():
    info = """Installation Wizard version 1.0.3

Welcome to the guided installation process for the file-sharing server named ultron-server.
Kindly proceed by selecting your desired option.."""
    window = tk.Tk()
    window.title("Installation Wizard")
    window.resizable(width=False, height=False)
    window.rowconfigure(0, minsize=150, weight=1)
    window.columnconfigure(1, minsize=0, weight=1)
    label = tk.Label(window, text=info)
    frm_buttons = tk.Frame(window, relief=tk.RAISED, bd=2)
    btn_install = tk.Button(frm_buttons, text="Install", command=install_guide)
    btn_uninstall = tk.Button(frm_buttons, text="Uninstall", command=uninstall_guide)
    btn_install.grid(row=0, column=0, sticky="e", padx=140, pady=5)
    btn_uninstall.grid(row=0, column=1, sticky="w", pady=5)
    frm_buttons.grid(row=1, column=0, sticky="ews")
    label.grid(row=0, column=0, sticky="nsew")
    window.mainloop()


if __name__ in '__main__':
    start_wizard()
