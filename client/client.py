import requests
from tkinter.filedialog import askopenfilename
from tkinter.filedialog import asksaveasfile
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import typer
from rich.prompt import Prompt
from rich.prompt import Confirm
from rich import print
import base64
from rich.console import Console
from rich.table import Table
import secrets

console = Console()


app = typer.Typer()

myurl = 'http://127.0.0.1:8000'

userid = ""
username = Prompt.ask("[bold]What is your username? (Leave blank to create a new user)[/bold]")


def createPublicPrivateKeys(username):
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
    sender_random_key = secrets.token_bytes(32)

    return sender_random_key

def encryptAndSignFile(filename, file_content, shared_key, private_key):
    # Encrypt the file using AES - CTR
    nonce = secrets.token_bytes(16) # same length as the block size
    cipher = Cipher(algorithms.AES(shared_key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(file_content) + encryptor.finalize()
    print("File encrypted!")

    file_signature = private_key.sign(
        nonce + ct,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    encrypted_file_name = filename + ".enc"
    with open(encrypted_file_name, "wb") as encrypted_file:
        encrypted_file.write(nonce)
        encrypted_file.write(ct)

    return encrypted_file_name, file_signature




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

    # Encoding
    s_encoded_key_ciphertext = base64.b64encode(s_encrypted_key).decode('utf-8')
    s_encoded_signature = base64.b64encode(s_signature).decode('utf-8')

    return s_encoded_key_ciphertext, s_encoded_signature


def checkIfUser(username):
    if username == "" or not os.path.isdir(f"./userdata/{username}"):
        username = Prompt.ask("[bold green]Enter your new username![/bold green]")
        if not os.path.isdir(f"./userdata"):
            os.mkdir("./userdata")
        os.mkdir(f"./userdata/{username}")
    
        public_pem = createPublicPrivateKeys(username)

        f_public = open(f"./userdata/{username}/public_key.pem", "wb")
        f_public.write(public_pem)
        f_username = open(f"./userdata/{username}/username.txt", "w")
        f_username.write(username)
        response = requests.post(f"{myurl}/add-user", json={
            "username": username,
            "public_key": public_pem.decode()
        })
        userid = str(response.json()["userid"])
        f_userid = open(f"./userdata/{username}/userid.txt", "w")
        f_userid.write(userid)
    else:
        userid = open(f"./userdata/{username}/userid.txt", "r").readline()
        username = open(f"./userdata/{username}/username.txt", "r").readline()
    return userid




userid = checkIfUser(username)

while True:
    table = Table("Option", "Description")
    table.add_row("read", "See files sent to you")
    table.add_row("send", "Send a file to someone else")
    console.print(table)

    choice = Prompt.ask("What would you like to do?")

    if choice == "read":
        response = requests.get(f"{myurl}/messages?user={userid}")
        messages = response.json()
        table = Table("ID", "Sender")
        for message in messages:
            table.add_row(str(message["id"]), str(message["sender"]))
        console.print(table)
        chosen_id = int(Prompt.ask("Which file would you like to read? (Enter ID)"))
        file_response = requests.get(f"{myurl}/file?message_id={chosen_id}")
        file_ciphertext = file_response.content
        file_plaintext = ""
        with open(f"./userdata/{username}/private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
            file_plaintext = private_key.decrypt(
                file_ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        print("[bold]File Content:\n[/bold]")
        print("\n")
        print(file_plaintext)
        print("\n")
        if Confirm.ask("[bold]Do you want to save this file?[/bold]"):
            f = asksaveasfile(mode='wb')
            f.write(file_plaintext)
            f.close()

    if choice == "send":
        users = getAndPrintUsers()
        option = Prompt.ask("Please choose the number of the receiving user (enter 'cancel' to cancel)")
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

        sender_random_key = createSharedKey()

        encrypted_key, s_signature = encryptSignSharedKey(sender_random_key, recipient_public_key, private_key)

        # Encrypt the file using AES - CTR
        print("Please choose a file:")
        filename = askopenfilename()
        file = open(filename, 'rb')
        file_content = file.read()
        encrypted_file_name, file_signature = encryptAndSignFile(filename, file_content, sender_random_key, private_key)

        with open(encrypted_file_name, 'rb') as encrypted_file:
            file = file_to_send = {'file': encrypted_file}
            try:
                requests.post(f"{myurl}/send-file?sender={userid}&recipient={recipient}&shared_key={encrypted_key}&sender_signature={s_signature}&file_signature={file_signature}", files=file)
            except Exception as e:
                print(e)

        encrypted_file.close()
        os.remove(encrypted_file_name)
        print("File sent!")
