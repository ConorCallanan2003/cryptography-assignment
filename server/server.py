import json
import time
import os
import jwt
import base64
from db import *
from fastapi import FastAPI, Response, UploadFile
from playhouse.shortcuts import model_to_dict
from pydantic import BaseModel
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

app = FastAPI()

class CreateUserModel(BaseModel):
    username: str
    password: str
    public_key: str

class MessageModel(BaseModel):
    sender: int
    recipient: int
    file: int
    shared_key : str

class SignInDetails(BaseModel):
    username: str
    password: str

class AuthenticatedRequest(BaseModel):
    jwt: str

class SendFileRequest(AuthenticatedRequest):
    file: UploadFile
    recipient: int


@app.post("/create-user")
async def create_user(user: CreateUserModel):
    # Add regex password validation
    newUser = User.create(username = user.username, public_key = user.public_key)
    newUser.save()
    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    digest = kdf.derive(str.encode(user.password))
    newPassword = Password.create(user=newUser.id, hashed_pw=base64.b64encode(digest), salt=base64.b64encode(salt))
    newPassword.save()
    return Response(status_code=200, content=json.dumps({"status": "Success", "message": "New user has been created!", "userid": newUser.id}))

@app.post("/sign-in")
async def sign_in(sign_in_details: SignInDetails):
    start = time.time()
    user = User.get_or_none(User.username == sign_in_details.username)
    if user == None:
        end = time.time()
        if (end - start < 0.5):
            time.sleep(0.5 - (end - start))
    user_password = Password.get_or_none(Password.user == user.id)
    if user_password == None:
        end = time.time()
        if (end - start < 0.5):
            time.sleep(0.5 - (end - start))
    kdf = Scrypt(
        salt=user_password.salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    kdf.verify(str.encode(sign_in_details.password), base64.b64decode(user_password.hashed_pw))

    session_jwt = jwt.encode({"user_id": user.id, "iat": time.time(),"exp": time.time() + 1800, "count": 0}, jwt_secret, algorithm="HS256")

    end = time.time()

    if (end - start < 0.5):
        time.sleep(0.5 - (end - start))

    return Response(status_code=200, content=json.dumps({"status": "signed in", "jwt": session_jwt}))

@app.post("/send-file")
async def create_upload_file(body: SendFileRequest):
    file = body.file
    jwt_data = jwt.decode(body.jwt, jwt_secret, algorithms="HS256")
    sender_id = jwt_data[""]
    content = await file.read()
    newFile = File.create(content=content)
    newMessage = Message.create(sender=sender_id, recipient=body.recipient, file=newFile.id)
    newFile.save()
    newMessage.save()
    return Response(status_code=200, content=f"Success: File sent")


@app.post("/send-file")
async def create_upload_file(file: UploadFile, sender: int, recipient: int):
    content = await file.read()
    newFile = File.create(content=content)
    newMessage = Message.create(sender=sender, recipient=recipient, file=newFile.id, shared_key="shared_key")
    newFile.save()
    newMessage.save()
    return Response(status_code=200, content=f"Success: File sent")

@app.get("/users")
async def get_users():
    response_content = []
    users = User.select()
    for user in users:
        response_content.append(model_to_dict(user))

    return Response(status_code=200, content=json.dumps(response_content))

@app.get("/messages")
async def get_messages(user: int):
    response_content = []
    print(user)
    messages = Message.select().where(Message.recipient == user)
    for message in messages:
        response_content.append({"id": message.id, "sender": message.sender.username})

    return Response(status_code=200, content=json.dumps(response_content))

@app.get("/file")
async def get_file(message_id: int):
    file = File.select().where(File.id == message_id)
    if len(file)!= 1:
        return Response(status_code=404, content="No such file")
    return Response(status_code=200, content=file[0].content)

@app.get("/test")
async def test():
    return Response(status_code=200, content="Server is running")
