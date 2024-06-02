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

http = urllib3.PoolManager()

app = typer.Typer()

myurl = 'http://127.0.0.1:8000'

userid = ""
username = Prompt.ask("[bold]What is your username? (Leave blank to create a new user)[/bold]")

session_jwt = ""

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

def getPublicKey(userid):
    users = requests.get(f"{myurl}/users").json()
    public_key = ""
    for user in users:
        if user["id"] == userid:
            public_key_string = user["public_key"]
            break

    public_key = serialization.load_pem_public_key(
        public_key_string.encode("utf-8"),
    )
    return public_key

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

    return s_encrypted_key, s_signature

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
    
        public_pem = createPublicPrivateKeys(username)

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
    return userid

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
        sender_public_key = getPublicKey(sender_id)
        with open(f"./userdata/{username}/private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            
        isValidKeySignature = verifySignature(keySignature, signedkey, sender_public_key)
        if not isValidKeySignature:
            print("Warning: The key has been tampered with and is now invalid.\n")
            continue
        
        decrypted_symmetric_key = decryptSignedKey(encryptedKey, private_key)

        isValidFileSignature = verifySignature(fileSignature, signedFile, sender_public_key)
        if not isValidFileSignature:
            print("Warning: The file has been tampered with and is now invalid.\n")
            continue
        
        nonce = file_ciphertext[:16]
        extracted_ciphertext = file_ciphertext[16:]
        file_plaintext = decryptFile(extracted_ciphertext, decrypted_symmetric_key, nonce)

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

        symmetric_key = createSharedKey()

        encrypted_key, s_signature = encryptSignSharedKey(sender_random_key, recipient_public_key, private_key)


        print("Please choose a file:")
        filename = askopenfilename()
        file = open(filename, 'rb')
        file_content = file.read()
        encrypted_file_name, file_signature = encryptAndSignFile(filename, file_content, sender_random_key, private_key)

        with open(encrypted_file_name, 'rb') as encrypted_file:
            file = {'file': encrypted_file}
            try:
                requests.post(f"{myurl}/send-file?sender={userid}&recipient={recipient}&shared_key={encrypted_key}&sender_signature={s_signature}&file_signature={file_signature}", files=file)
            except Exception as e:
                print(e)

        encrypted_file = open(filename + ".tmp", "wb")
        encrypted_file.write(bytes(file_content))
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
