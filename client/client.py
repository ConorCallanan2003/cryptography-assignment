import requests
from tkinter.filedialog import askopenfilename
from tkinter.filedialog import asksaveasfile
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import typer
from rich.prompt import Prompt
from rich import print

from rich.console import Console
from rich.table import Table

console = Console()


app = typer.Typer()

myurl = 'http://127.0.0.1:8000'

userid = ""
username = Prompt.ask("[bold]What is your username? (Leave blank to create a new user)[/bold]")

if username == "" or not os.path.isdir(f"./userdata/{username}"):
    username = Prompt.ask("[bold green]Enter your new username![/bold green]")
    os.mkdir(f"./userdata/{username}")
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
    
    

while True:
    table = Table("Option", "Description")
    table.add_row("read", "See files sent to you")
    table.add_row("send", "Send a file to someone else")
    console.print(table)

    choice = Prompt.ask("What would you like to do?")

    if choice == "read":
        response = requests.get(f"{myurl}/files?user={userid}")
        files = response.json()
        table = Table("ID", "Sender")
        for file in files:
            table.add_row(str(file["id"]), str(file["sender"]))
        console.print(table)
        chosen_id = int(Prompt.ask("Which file would you like to read? (Enter ID)"))
        file = list(filter(lambda x: int(x["id"]) == chosen_id, files))[0]["file"]
        print("[bold]File Content:\n[/bold]")
        print(file)
        if Prompt.confirm("[bold]Do you want to save this file?[/bold]"):
            f = asksaveasfile(mode='wb')
            f.write(bytes(file))

    if choice == "send":
        users = requests.get(f"{myurl}/users").json()
        table = Table("No. ", "Username", "UserID")
        for index, user in enumerate(users):
            table.add_row(str(index+1), str(user["username"]), str(user["id"]))  
        console.print(table)
        option = Prompt.ask("Please choose a user (enter 'cancel' to cancel)")
        if option == "cancel":
            continue
        recipient = users[int(option)-1]["id"]
        print("Please choose a file:")
        filename = askopenfilename()
        file = {'file': open(filename, 'rb')}
        requests.post(f"{myurl}/send-file?sender={userid}&recipient={recipient}", files=file)
        print("File sent!")