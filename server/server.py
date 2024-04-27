from fastapi.responses import FileResponse
from db import *
from fastapi import FastAPI, Response, UploadFile
import json
from playhouse.shortcuts import model_to_dict
from pydantic import BaseModel

app = FastAPI()

class UserModel(BaseModel):
    username: str
    public_key: str


@app.post("/add-user")
async def create_user(user: UserModel):
    newUser = User.create(username = user.username, public_key = user.public_key)
    newUser.save()
    return Response(status_code=200, content=json.dumps({"userid": newUser.id}))


@app.post("/send-file")
async def create_upload_file(file: UploadFile, sender: int, recipient: int):
    content = await file.read()
    newFile = File.create(content=content)
    newMessage = Message.create(sender=sender, recipient=recipient, file=newFile.id)
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

@app.get("/files")
async def get_files(user: int):
    response_content = []
    messages = Message.select().where(Message.recipient == user)
    for message in messages:
        response_content.append({"id": message.id, "sender": message.sender.username, "file": message.file.content.decode().replace("'", '"')})

    return Response(status_code=200, content=json.dumps(response_content))
