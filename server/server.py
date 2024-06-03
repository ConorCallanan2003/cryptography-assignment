import json
import time
import secrets
import requests
from art import *
from datetime import datetime
from typing import Annotated
import jwt
import base64
from db import *
import re
from fastapi import FastAPI, Form, HTTPException, Header, Response, UploadFile
from playhouse.shortcuts import model_to_dict
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

jwt_secret = secrets.token_bytes(32)
captch_secret = secrets.token_bytes(32)
MAX_FAILED_ATTEMPTS = 3

app = FastAPI()

class CreateUserModel(BaseModel):
    username: str
    password: str
    public_key: str

class SignInDetails(BaseModel):
    username: str
    password: str

class AuthenticatedRequest(BaseModel):
    jwt: str

class SendFileRequest(AuthenticatedRequest):
    recipient: int
    
def authenticate_jwt(authorization):
    auth_token = authorization.replace("Bearer ", "")
    try:
        session_details = jwt.decode(auth_token, jwt_secret, algorithms="HS256")
    except:
        return Response(status_code=401, content=f"Error: Invalid authentication token")
    isBlockedJWT = BlockedJWTs.get_or_none(BlockedJWTs.jwt == auth_token)
    if isBlockedJWT is not None:
        return Response(status_code=401, content=f"Error: Authentication token blocked")
    exp =  session_details["exp"]
    exp_dt = datetime.fromtimestamp(exp/1000.0)
    if (exp_dt > datetime.now()):
        return Response(status_code=401, content=f"Error: Authentication token expired")
    return session_details, auth_token

def revoke_jwt(jwt):
    blockedJWT = BlockedJWTs.create(jwt=jwt)
    blockedJWT.save()

@app.post("/create-user")
async def create_user(user: CreateUserModel, Authorization: Annotated[str, Header()]):
    session_details, _ = authenticate_jwt(Authorization)
    
    print(session_details)
    
    if "verified" not in session_details or session_details["verified"] is False:
        return Response(status_code=423, content=json.dumps({"status": "error", "message": "Unverified token. Please complete captcha"}))
    
    pattern = r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$"
    if not re.match(pattern, user.password):
        return Response(status_code=422, content=json.dumps({"status": "error", "message": "Insufficient password"}))
    try:
        newUser = User.create(username = user.username, public_key = user.public_key)
        newUser.save()
    except:
        raise HTTPException(status_code=423, detail="Username already exists")
    salt = secrets.token_bytes(16)
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

@app.get("/captcha")
async def captcha():
    challenge = requests.get("http://api.textcaptcha.com/myemail@example.com.json").json()
    answers = challenge["a"]
    question = challenge["q"]
    ascii_art_question = text2art(question.replace(" ", "\n"), "rand")
    jwt_data = {"iat": time.time(),"exp": time.time() + 1800}
    for index, answer in enumerate(answers):
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(captch_secret), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(str.encode(answer)) + encryptor.finalize()
        b64_ct = base64.b64encode(ct).decode("utf-8")
        b64_iv = base64.b64encode(iv).decode("utf-8")
        jwt_data[f"answer_{index}"] = b64_ct
        jwt_data[f"answeriv_{index}"] = b64_iv
    
    handshake_jwt = jwt.encode(jwt_data, jwt_secret, algorithm="HS256")
    return Response(status_code=200, content=json.dumps({"status": "captcha_sent", "jwt": handshake_jwt, "question": ascii_art_question}))

@app.post("/verify")
async def verify(Authorization: Annotated[str, Header()], answer: Annotated[str, Form()]):
    session_details, _ = authenticate_jwt(Authorization)
    answers = []
    for key in session_details:
        if len(key) > 7 and key[0:7] == "answer_":
            b64_ct = session_details[key]
            ct = base64.b64decode(b64_ct)
            b64_iv = session_details[key.replace("_", "iv_")]
            iv = base64.b64decode(b64_iv)
            cipher = Cipher(algorithms.AES(captch_secret), modes.CBC(iv))
            decryptor = cipher.decryptor()
            current_answer = decryptor.update(ct) + decryptor.finalize()
            answers.append(current_answer.decode("utf-8"))
    
    response_answer_hash = hashes.Hash(hashes.MD5())
    response_answer_hash.update(str.encode(answer))
    response_answer_hash = response_answer_hash.finalize().hex()
    
    correct = False
    
    for answer in answers:
        if answer == response_answer_hash:
            correct = True

    if correct:
        handshake_jwt = jwt.encode({"verified": True, "user_id": None, "iat": time.time(),"exp": time.time() + 1800, "failed_attempts": 0}, jwt_secret, algorithm="HS256")
        return Response(status_code=200, content=json.dumps({"status": "handshake", "jwt": handshake_jwt}))
    
    return Response(status_code=401, content=json.dumps({"status": "failed captcha"}))
    
@app.post("/sign-in")
async def sign_in(username: Annotated[str, Form()], password: Annotated[str, Form()], Authorization: Annotated[str, Header()]):
    start = time.time()
    
    session_details, request_jwt = authenticate_jwt(Authorization)
    
    if "verified" not in session_details or session_details["verified"] is False:
        return Response(status_code=423, content=json.dumps({"status": "error", "message": "Unverified token. Please complete captcha"}))
    
    if session_details["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
        print("Too many failed login attempts")
        return Response(status_code=423, content=json.dumps({"status": "error", "message": "Too many failed login attempts"}))
    
    user = User.get_or_none(User.username == username)
    if user is None:
        end = time.time()
        if end - start < 0.5:
            time.sleep(0.5 - (end - start))
        return Response(status_code=500, content=json.dumps({"status": "error", "message": "Incorrect username and/or password"}))
    
    user_password = Password.get_or_none(Password.user == user.id)
    if user_password is None:
        end = time.time()
        if end - start < 0.5:
            time.sleep(0.5 - (end - start))
        return Response(status_code=500, content=json.dumps({"status": "error", "message": "Incorrect username and/or password"}))
    
    kdf = Scrypt(
        salt=base64.b64decode(user_password.salt),
        length=32,
        n=2**14,
        r=8,
        p=1,
    )

    try:
        kdf.verify(password.encode(), base64.b64decode(user_password.hashed_pw))
    except:
        failed_attempts = session_details["failed_attempts"]
        failed_attempts += 1
        token = jwt.encode({"verified": True, "user_id": user.id, "iat": time.time(),"exp": time.time() + 1800, "failed_attempts": failed_attempts}, jwt_secret, algorithm="HS256")
        revoke_jwt(request_jwt)
        return Response(status_code=401, content=json.dumps({"status": "error", "message": "Incorrect username and/or password", "jwt": token}))

    session_jwt = jwt.encode({"user_id": user.id, "iat": time.time(), "exp": time.time() + 1800}, jwt_secret, algorithm="HS256")
    end = time.time()

    if end - start < 0.5:
        time.sleep(0.5 - (end - start))
    print(f"User {username} signed in")
    return Response(status_code=200, content=json.dumps({"status": "signed in", "jwt": session_jwt}))



@app.post("/send-file")
async def create_upload_file(file: Annotated[UploadFile, File()], recipient: Annotated[str, Form()], shared_key: Annotated[str, Form()], sender_signature: Annotated[str, Form()], file_signature: Annotated[str, Form()], Authorization: Annotated[str, Header()]):
    session_details, request_jwt = authenticate_jwt(Authorization)
    revoke_jwt(request_jwt)
    session_details["iat"] = time.time()
    session_details["exp"] = time.time() + 1800
    if (isinstance(session_details, Response)):
        return session_details
    content = await file.read()
    newFile = File.create(content=content)
    newMessage = Message.create(sender=session_details["user_id"], recipient=recipient, file=newFile.id, shared_key=shared_key, sender_signature=sender_signature, file_signature=file_signature)
    newFile.save()
    newMessage.save()
    new_jwt = jwt.encode(session_details, jwt_secret, algorithm="HS256")
    return Response(status_code=200, content=json.dumps({"status": "success", "message": "File sent", "jwt": new_jwt}))

@app.get("/users")
async def get_users(Authorization: Annotated[str, Header()]):
    session_details, _ = authenticate_jwt(Authorization)
    
    if (isinstance(session_details, Response)):
        return session_details

    response_content = []
    users = User.select()

    for user in users:
        response_content.append(model_to_dict(user))

    return Response(status_code=200, content=json.dumps(response_content))

@app.get("/messages")
async def get_messages(Authorization: Annotated[str, Header()]):
    session_details, _ = authenticate_jwt(Authorization)
    if (isinstance(session_details, Response)):
        return session_details
    user = session_details["user_id"]
    response_content = []
    messages = Message.select().where(Message.recipient == user)
    for message in messages:
        response_content.append({"id": message.id, "sender": message.sender.username})

    return Response(status_code=200, content=json.dumps(response_content))

@app.get("/file")
async def get_file(message_id: int, Authorization: Annotated[str, Header()]):
    session_details, _ = authenticate_jwt(Authorization)
    if (isinstance(session_details, Response)):
        return session_details
    message = Message.get_or_none(Message.id == message_id)
    file = File.get_or_none(File.id == message_id)
    if file is None or message is None:
        return Response(status_code=404, content="No such file")
    metadata = {
        "shared_secret": message.shared_key,
        "sender_signature": message.sender_signature,
        "sender_id": message.sender.id,
        "file_signature": message.file_signature
    }
    return Response(status_code=200, content=file.content, headers={"file-metadata": json.dumps(metadata)})

@app.get("/test")
async def test():
    return Response(status_code=200, content="Server is running")
