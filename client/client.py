import os
import jwt
import urllib3
import json
from tkinter.filedialog import askopenfilename
from tkinter.filedialog import asksaveasfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from sympy import content
import typer
from rich.prompt import Prompt
from rich.prompt import Confirm
from rich import print

from rich.console import Console
from rich.table import Table
import secrets

console = Console()

http = urllib3.PoolManager()

app = typer.Typer()

myurl = 'http://127.0.0.1:8000'

userid = ""
username = Prompt.ask("[bold]What is your username? (Leave blank to create a new user)[/bold]")

session_jwt = ""

def createPublicPrivateKeys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    f_private = open(f"./userdata/{username}/private_key.pem", "wb")
    f_private.write(private_pem)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_pem


def getAndPrintUsers():
    users_response_raw = http.request("GET", f"{myurl}/users", headers={"Authorization": "Bearer " + session_jwt})
    users_response_decoded = users_response_raw.data.decode("utf-8")
    users_json = json.loads(users_response_decoded)
    users = list(filter(lambda x: x["id"]!= int(userid), users_json))
    table = Table("No. ", "Username", "UserID")
    for index, user in enumerate(users):
        table.add_row(str(index+1), str(user["username"]), str(user["id"]))
    console.print(table)
    return users


def createSharedKey():
    sender_random_key = os.urandom(16)

    return sender_random_key


def encryptSignSharedKey(sharedKey, r_public_key, s_private_key):
    # Encryption
    s_encrypted_key = r_public_key.encrypt(
        sharedKey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Signature - PSS
    s_signature = s_private_key.sign(
        s_encrypted_key,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return s_encrypted_key, s_signature

def encryptSymmetric(symmetricKey, content):
    nonce = ""
    encrypted_content = content
    return nonce, encrypted_content

def decryptSymmetric(symmetricKey, encrypted_content, nonce):
    nonce = ""
    content = encrypted_content
    return content


def checkIfUser():
    global username
    global userid
    newUser = False
    if not os.path.isdir(f"./userdata/{username}"):
        print("User does not exist. \n")
        newUser = True
    if username == "" or newUser:
        username = Prompt.ask("[bold green]Enter your new username![/bold green]")
        password = Prompt.ask("[bold red]Enter your new password![/bold red]")
        if not os.path.isdir(f"./userdata"):
            os.mkdir("./userdata")
        os.mkdir(f"./userdata/{username}")
    
        public_pem = createPublicPrivateKeys()

        f_public = open(f"./userdata/{username}/public_key.pem", "wb")
        f_public.write(public_pem)
        f_username = open(f"./userdata/{username}/username.txt", "w")
        f_username.write(username)
        create_user_data = {"username": username, "password": password}
        encoded_create_user_data = json.dumps(create_user_data).encode('utf-8')
        create_user_response_raw = http.request("POST", f"{myurl}/create-user", body=encoded_create_user_data)
        create_user_response_decoded = create_user_response_raw.data.decode("utf-8")
        create_user_json = json.loads(create_user_response_decoded)
        userid = str(create_user_json["userid"])
        userid_file = open(f"./userdata/{username}/userid.txt", "w")
        userid_file.write(userid)
        print("[bold blue]New user has been created![/bold blue]")
    else:
        userid = open(f"./userdata/{username}/userid.txt", "r").readline()
        username = open(f"./userdata/{username}/username.txt", "r").readline()

def signIn(username, password):
    global session_jwt
    sign_in_data = {"username": username, "password": password}
    encoded_sign_in_data = json.dumps(sign_in_data).encode('utf-8')
    sign_in_response_raw = http.request("POST", f"{myurl}/sign-in", body=encoded_sign_in_data)
    sign_in_response_decoded = sign_in_response_raw.data.decode("utf-8")
    sign_in_response_json = json.loads(sign_in_response_decoded)
    if sign_in_response_raw.status != 200:
        print("\n[bold red]Error signing in...[/bold red]\n")
    session_jwt = sign_in_response_json["jwt"]

checkIfUser()

password = Prompt.ask("Enter your password: ")

signIn(username, password)

while True:
    if session_jwt == "":
        print("Invalid session token. Please try logging out and logging in again.")
    
    session_details = jwt.decode(session_jwt, options={"verify_signature": False})
        
    table = Table("Option", "Description")
    if session_details is not None:
        table.add_row("read", "See files sent to you")
        table.add_row("send", "Send a file to someone else")

    table.add_row("logout", "Sign out of this account")
    console.print(table)

    choice = Prompt.ask("What would you like to do?")

    if choice == "read":
        try:
            messages_response_raw = http.request("GET", f"{myurl}/messages?user={userid}", headers={"Authorization": "Bearer " + session_jwt})
            messages_response_decoded = messages_response_raw.data.decode("utf-8")
            messages_json = json.loads(messages_response_decoded)
            table = Table("ID", "Sender")
            for message in messages_json:
                table.add_row(str(message["id"]), str(message["sender"]))
            console.print(table)
            chosen_id = int(Prompt.ask("Which file would you like to read? (Enter ID)"))
            file_response_raw = http.request("GET", f"{myurl}/file?message_id={chosen_id}", headers={"Authorization": "Bearer " + session_jwt})
            file_response_json = json.loads(file_response_raw.headers["file-metadata"])
            encrypted_shared_secret = file_response_json["shared_secret"]
            nonce = file_response_json["nonce"]
            file_ciphertext = file_response_raw.data
            file_plaintext = ""
            with open(f"./userdata/{username}/private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
                symmetric_key = private_key.decrypt(
                    encrypted_shared_secret,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                file_content = decryptSymmetric(symmetric_key, file_ciphertext, nonce)
            print("[bold]File Content:\n[/bold]")
            print("\n")
            print(file_plaintext)
            print("\n")
            if Confirm.ask("[bold]Do you want to save this file?[/bold]"):
                f = asksaveasfile(mode='wb')
                f.write(file_plaintext)
                f.close()
        except:
            print("\nSomething went wrong...\n")
            continue

    if choice == "send":
        try:
            users = getAndPrintUsers()
            option = Prompt.ask("Please choose a user (enter 'cancel' to cancel)")
            if option == "cancel":
                continue
            recipient = users[int(option)-1]["id"]
            recipient_public_key_string = users[int(option)-1]["public_key"]
            recipient_public_key = serialization.load_pem_public_key(
                recipient_public_key_string.encode("utf-8"),
            )

            with open(f"./userdata/{username}/private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )

            symmetric_key = createSharedKey()

            encrypted_key, s_signature = encryptSignSharedKey(symmetric_key, recipient_public_key, private_key)

            print("Please choose a file:")
            filename = askopenfilename()
            file = open(filename, 'rb')
            file_content = file.read()
            encrypted_file = open(filename + ".tmp", "wb")
            nonce, encrypted_file_content = encryptSymmetric(symmetric_key, file_content)
            encrypted_file.write(bytes(encrypted_file_content))
            encrypted_file.close()
            fields = {
                "recipient": recipient,
                "shared_key": encrypted_key,
                "sender_signature": s_signature,
                "file": (filename + ".tmp", open(filename + ".tmp").read()),
            }
            
            body, header = urllib3.encode_multipart_formdata(fields)

            http.request("POST", f"{myurl}/send-file", headers={"Authorization": "Bearer " + session_jwt, "content-type": header}, body=body)
            os.remove(filename + ".tmp")
            print("File sent!")
        except KeyboardInterrupt:
            print("\nSomething went wrong...\n")
            continue

    if choice == "logout":
        userid = ""
        session_jwt = ""
        username = Prompt.ask("[bold]What is your username? (Leave blank to create a new user)[/bold]")
        checkIfUser()
