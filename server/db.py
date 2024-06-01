from inspect import signature
from peewee import BlobField, CharField, ForeignKeyField, Model, SqliteDatabase, TextField
db = SqliteDatabase('database.db')

class User(Model):
    username = CharField()
    public_key = TextField()

    class Meta:
        database = db

class File(Model):
    content = BlobField()

    class Meta:
        database = db

class Message(Model):
    sender = ForeignKeyField(User, backref="messages_sent")
    recipient = ForeignKeyField(User, backref="messages_received")
    file = ForeignKeyField(File, backref="message")
    shared_key = CharField()
    sender_signature = CharField()

    class Meta:
        database = db


db.connect()

db.create_tables([User, File, Message])
