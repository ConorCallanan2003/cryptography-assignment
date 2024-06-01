import requests
from tkinter.filedialog import askopenfilename
from tkinter.filedialog import asksaveasfile
import os
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


app = typer.Typer()

myurl = 'http://127.0.0.1:8000'

userid = ""
username = Prompt.ask("[bold]What is your username? (Leave blank to create a new user)[/bold]")


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
    users = requests.get(f"{myurl}/users").json()
    users = list(filter(lambda x: x["id"]!= int(userid), users))
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
    if username == "" or not os.path.isdir(f"./userdata/{username}"):
        username = Prompt.ask("[bold green]Enter your new username![/bold green]")
        if not os.path.isdir(f"./userdata"):
            os.mkdir("./userdata")
        os.mkdir(f"./userdata/{username}")
    
        public_pem = createPublicPrivateKeys()

        f_public = open(f"./userdata/{username}/public_key.pem", "wb")
        f_public.write(public_pem)
        f_username = open(f"./userdata/{username}/username.txt", "w")
        f_username.write(username)
        response = requests.post(f"{myurl}/add-user", json={
            "username": username,
            "public_key": public_pem.decode()
        })
        userid = str(response.json()["userid"])
        userid_file = open(f"./userdata/{username}/userid.txt", "w")
        userid_file.write(userid)
    else:
        userid = open(f"./userdata/{username}/userid.txt", "r").readline()
        username = open(f"./userdata/{username}/username.txt", "r").readline()

checkIfUser()

while True:
    table = Table("Option", "Description")
    table.add_row("read", "See files sent to you")
    table.add_row("send", "Send a file to someone else")
    table.add_row("logout", "Sign out of this account")
    console.print(table)

    choice = Prompt.ask("What would you like to do?")

    if choice == "read":
        try:
            response = requests.get(f"{myurl}/messages?user={userid}")
            messages = response.json()
            table = Table("ID", "Sender")
            for message in messages:
                table.add_row(str(message["id"]), str(message["sender"]))
            console.print(table)
            chosen_id = int(Prompt.ask("Which file would you like to read? (Enter ID)"))
            file_response = requests.get(f"{myurl}/file?message_id={chosen_id}")
            encrypted_shared_secret = file_response.json()["shared_secret"]
            nonce = file_response.json()["nonce"]
            file_ciphertext = file_response.content
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
            file = {'file': open(filename + ".tmp", 'rb')}
            requests.post(f"{myurl}/send-file?sender={userid}&recipient={recipient}&shared_key={encrypted_key}&sender_signature={s_signature}", files=file)
            os.remove(filename + ".tmp")
            print("File sent!")
        except:
            print("\nSomething went wrong...\n")
            continue

    if choice == "logout":
        userid = ""
        username = Prompt.ask("[bold]What is your username? (Leave blank to create a new user)[/bold]")
        checkIfUser()
