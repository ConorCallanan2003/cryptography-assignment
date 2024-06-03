import os
import jwt
import urllib3
import json
import base64
import typer
import secrets
import re
from tkinter.filedialog import askopenfilename
from tkinter.filedialog import askdirectory
from tkinter.filedialog import asksaveasfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rich.prompt import Prompt
from rich.prompt import Confirm
from rich import print
from rich.console import Console
from rich.table import Table

console = Console()

http = urllib3.PoolManager()

app = typer.Typer()

myurl = 'http://127.0.0.1:8000'

userid = ""

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
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_pem, private_pem

def getPublicKey(userid):
    users_response_raw = http.request("GET", f"{myurl}/users", headers={"Authorization": "Bearer " + session_jwt})
    users_response_decoded = users_response_raw.data.decode("utf-8")
    users_json = json.loads(users_response_decoded)
    public_key = ""
    for user in users_json:
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
    
    file_content = nonce + ct


    file_signature = private_key.sign(
        file_content,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    encrypted_file_name = filename + ".enc"
    with open(encrypted_file_name, "wb") as encrypted_file:
        encrypted_file.write(file_content)
    
    s_encoded_file_signature = base64.b64encode(file_signature)

    return encrypted_file_name, s_encoded_file_signature




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
    s_encoded_key_ciphertext = base64.b64encode(s_encrypted_key)
    s_encoded_signature = base64.b64encode(s_signature)
    
    return s_encoded_key_ciphertext, s_encoded_signature

def verifyKeySignature(encoded_signed_key, encoded_signature, sender_public_key):
    decoded_key = base64.b64decode(encoded_signed_key)
    decoded_signature = base64.b64decode(encoded_signature)
    try:
        sender_public_key.verify(
            decoded_signature,
            decoded_key,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False
    
def verifyFileSignature(signature, signedFile, sender_public_key):
    decoded_signature = base64.b64decode(signature)
    try:
        sender_public_key.verify(
            decoded_signature,
            signedFile,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False
    
    
def decryptSignedKey(encryptedKey, receiver_private_key):
    decoded_encrypted_key = base64.b64decode(encryptedKey)
    # Decryption
    decrypted_key = receiver_private_key.decrypt(
        decoded_encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

def decryptFile(file_ciphertext, symmetric_key, nonce):
    # AES CTR mode with symmetric key
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    decrypted_plaintext = decryptor.update(file_ciphertext) + decryptor.finalize()
    return decrypted_plaintext

def checkIfUser():
    global username
    global userid
    global password

    pattern = r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$"
    signed_up = False
    signed_in = False
    
    while not signed_in and not signed_up:
        if username == "":
            while not signed_up:
                print("[bold]Please choose where you would like to store your user data![/bold]")
                userdata_path = askdirectory()
                
                if not os.path.isdir(userdata_path):
                    os.mkdir(userdata_path)
                username = Prompt.ask("[bold green]Enter your new username![/bold green]")
                password = Prompt.ask(prompt="[bold blue]Enter your new password![/bold blue] ", password=True)
                while not re.match(pattern, password):
                    password = Prompt.ask("[bold red]Password must contain at least one uppercase, one lowercase letter, one number and be at least eight characters in length.[/bold red] [bold blue]\nPlease enter a valid password![/bold blue]", password=True)
            
                public_pem, private_pem = createPublicPrivateKeys(username)
                
                create_user_data = {"username": username, "password": password, "public_key": public_pem.decode("utf-8")}
                create_user_response_raw = http.request("POST", f"{myurl}/create-user", json=create_user_data, headers={"Authorization": f"Bearer {session_jwt}", "Content-Type": "application/json"})
                if create_user_response_raw.status == 423:
                    print("[bold red]Username already taken![/bold red]\n")
                    continue
                else:
                    signed_up = True
                create_user_response_decoded = create_user_response_raw.data.decode("utf-8")
                create_user_json = json.loads(create_user_response_decoded)
                
                if not os.path.isdir(f"./userdata"):
                    os.mkdir("./userdata")
                    
                if not os.path.isdir(f"./userdata/{username}"):
                    os.mkdir(f"./userdata/{username}")
                
                f_private = open(userdata_path + "/private_key.pem", "wb")
                f_private.write(private_pem)
                
                f_public = open(userdata_path + "/public_key.pem", "wb")
                f_public.write(public_pem)
                f_username = open(userdata_path + "/username.txt", "w")
                f_username.write(username)

                userid = str(create_user_json["userid"])
                userid_file = open(userdata_path + "/userid.txt", "w")
                userid_file.write(userid)

                print("[bold blue]New user has been created![/bold blue]")
        else:
            print("[bold]Please select your user data directory[/bold]")
            userdata_path = askdirectory()
            if not os.path.isdir(userdata_path):
                print("[bold red]Directory does not exist![/bold red]")
                continue
            userid = open(userdata_path + "/userid.txt", "r").readline()
            username = open(userdata_path + "/username.txt", "r").readline()
            password = Prompt.ask(prompt='Enter your password: ', password=True)
            signed_in = True
        

def signIn(username):
    global session_jwt
    global password

    while True:

        fields = {
            "username": username,
            "password": password
        }
        body, header = urllib3.encode_multipart_formdata(fields)

        sign_in_response_raw = http.request(
            "POST", 
            f"{myurl}/sign-in",
            headers={"Authorization": f"Bearer {session_jwt}", "Content-Type": header},
            body=body
        )
        sign_in_response_decoded = sign_in_response_raw.data.decode("utf-8")
        sign_in_response_json = json.loads(sign_in_response_decoded)

        session_jwt = sign_in_response_json["jwt"]

        if sign_in_response_raw.status == 401:
            print("\n[bold red]Error signing in...[/bold red]\n")
            password = Prompt.ask(prompt='Enter your password: ', password=True)
            
        elif sign_in_response_raw.status == 423:
            print("\n[bold red]Too many attempts...[/bold red]\n")
            return False

        elif sign_in_response_raw.status == 200:
            session_jwt = sign_in_response_json["jwt"]
            print("\n[bold green]Signed in successfully![/bold green]\n")
            return True

def robot_check():
    global session_jwt
    
    captcha_response = http.request("GET", f"{myurl}/captcha")
    captcha_response_json = json.loads(captcha_response.data.decode("utf-8"))
    session_jwt = captcha_response_json["jwt"]
    question = captcha_response_json["question"]

    answer = Prompt.ask(f"\n{question}\n[bold]Please answer this question to prove you are human! (lowercase only) [/bold]\nAnswer")

    fields = {
        "answer": answer
    }
                
    body, header = urllib3.encode_multipart_formdata(fields)

    verify_response = http.request("POST", f"{myurl}/verify", headers={"Authorization": "Bearer " + session_jwt, "content-type": header}, body=body)
    if verify_response.status != 200:
        print("\n[bold red]Error verifying... Try again. [/bold red]\n")
        exit()
    verify_response_json = json.loads(verify_response.data.decode("utf-8"))
    
    session_jwt = verify_response_json["jwt"]

while True:
    
    robot_check()

    username = Prompt.ask("[bold]What is your username? (Leave blank to create a new user)[/bold]")

    checkIfUser()

    signed_in = signIn(username)

    if not signed_in:
        print("Exiting...")
        exit()
    
    while True:
        if session_jwt is not None:
            try:
                session_details = jwt.decode(session_jwt, options={"verify_signature": False})
            except jwt.InvalidTokenError:
                print("\n[bold red]Invalid session token. Please sign in again.[/bold red]\n")
                signIn(username)
                continue
                
        table = Table("Option", "Description")
        if session_details is not None:
            table.add_row("read", "See files sent to you")
            table.add_row("send", "Send a file to someone else")

        table.add_row("logout", "Sign out of this account")
        console.print(table)

        choice = Prompt.ask("What would you like to do?")

        if choice == "read":
            try:
                messages_response_raw = http.request("GET", f"{myurl}/messages", headers={"Authorization": "Bearer " + session_jwt})
                messages_response_decoded = messages_response_raw.data.decode("utf-8")
                messages_json = json.loads(messages_response_decoded)
                table = Table("ID", "Sender")
                for message in messages_json:
                    table.add_row(str(message["id"]), str(message["sender"]))
                console.print(table)
                chosen_id = Prompt.ask("Which file would you like to read? (Enter ID)")
                if chosen_id == "cancel":
                    continue
                file_response_raw = http.request("GET", f"{myurl}/file?message_id={int(chosen_id)}", headers={"Authorization": "Bearer " + session_jwt})
                file_response_json = json.loads(file_response_raw.headers["file-metadata"])
                encrypted_shared_secret = file_response_json["shared_secret"]
                sender_id = file_response_json["sender_id"]
                shared_secret = file_response_json["shared_secret"]
                sender_signature = file_response_json["sender_signature"]
                file_signature = file_response_json["file_signature"]
                file_ciphertext = file_response_raw.data
                file_plaintext = ""
                sender_public_key = getPublicKey(sender_id)
                with open(f"./userdata/{username}/private_key.pem", "rb") as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        backend=default_backend()
                    )
                    
                isValidKeySignature = verifyKeySignature(shared_secret, sender_signature, sender_public_key)
                if not isValidKeySignature:
                    print("Warning: The key has been tampered with and is now invalid.\n")
                    continue
                
                decrypted_symmetric_key = decryptSignedKey(shared_secret, private_key)

                isValidFileSignature = verifyFileSignature(file_signature, file_ciphertext, sender_public_key)
                if not isValidFileSignature:
                    print("Warning: The file has been tampered with and is now invalid.\n")
                    continue
                
                nonce = file_ciphertext[:16]
                extracted_ciphertext = file_ciphertext[16:]
                file_plaintext = decryptFile(extracted_ciphertext, decrypted_symmetric_key, nonce)

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

                encrypted_key, s_signature = encryptSignSharedKey(symmetric_key, recipient_public_key, private_key)

                print("Please choose a file:")
                filename = askopenfilename()
                file = open(filename, 'rb')
                file_content = file.read()
                encrypted_file_name, file_signature = encryptAndSignFile(filename, file_content, symmetric_key, private_key)
                
                fields = {
                    "recipient": recipient,
                    "shared_key": encrypted_key,
                    "sender_signature": s_signature,
                    "file_signature": file_signature,
                    "file": (encrypted_file_name, open(encrypted_file_name, "rb").read()),
                }
                
                body, header = urllib3.encode_multipart_formdata(fields)

                send_file_response_raw = http.request("POST", f"{myurl}/send-file", headers={"Authorization": "Bearer " + session_jwt, "content-type": header}, body=body)
                send_file_response_decoded = send_file_response_raw.data.decode("utf-8")
                send_file_json = json.loads(send_file_response_decoded)
                session_jwt = send_file_json["jwt"]
                os.remove(encrypted_file_name)
                print("File sent!")
            except KeyboardInterrupt:
                print("\nSomething went wrong...\n")
                continue

        if choice == "logout":
            userid = ""
            session_jwt = ""
            break
