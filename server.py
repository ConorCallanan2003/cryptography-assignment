import sqlite3
from fastapi import FastAPI, Response, UploadFile
from starlette.responses import JSONResponse

app = FastAPI()

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

'''

HUGE SQL INJECTION RISK HERE - EXECUTING RAW SQL *ONLY*
FOR ROUGH V1 - NEEDS TO BE CHANGED

'''

@app.post("/add-user")
async def create_user(username: str, public_key: str):
    cursor.execute("INTO users (username, public_key) VALUES (?, ?);", [username, public_key])
    conn.commit()
    return Response(status_code=200)


@app.post("/upload-file")
async def create_upload_file(file: UploadFile, sender: int, recipient: int):
    content = await file.read()
    insertBlob = cursor.execute("INSERT INTO files (content) VALUES(?);", [sqlite3.Binary(content)])
    fileId = insertBlob.lastrowid
    cursor.execute("INSERT INTO messages (sender, recipient, file) VALUES(?, ?, ?);", [sender, recipient, fileId])
    conn.commit()
    return Response(status_code=200, content=f"Success: File uploaded | {content}")

@app.get("/users")
async def get_users():
    rows = cursor.execute("SELECT * FROM USERS")
    data = rows.fetchall()
