import binascii as ba
import hashlib as hl
import os
from flask import Flask,render_template,request,session
import pymongo as pmdb
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
app=Flask(__name__)
app.config.from_pyfile("config.py")
app.secret_key=os.urandom(16)
client=pmdb.MongoClient(app.config.get("db_client","localhost:27017"))
db=client.get_database(app.config.get("db_name","notes"))
coll=db.get_collection(app.config.get("coll_name","notes"))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/open",methods=["POST"])
def open():
    key=str(request.form.get("key"))
    key=(key*(16//len(key.encode('utf-8'))))if len(key)<16 else key
    key+=key[:16-len(key)]
    sha256=hl.sha256(key.encode()).hexdigest()
    note=coll.find_one({"hash":sha256})
    session["key"]=key
    session["hash"]=sha256
    if not note:
        coll.insert_one({"hash":sha256,"note":""})
        return "NoteCreated"
    aes=AES.new(bytes(key.encode('utf-8')),AES.MODE_ECB)
    return unpad(aes.decrypt(ba.unhexlify(note["note"])),16).decode('utf-8')

@app.route("/update",methods=["POST"])
def update():
    key=session["key"]
    newNote=request.form.get("note")
    note=coll.find_one({"hash":session["hash"]})
    aes=AES.new(bytes(key.encode('utf-8')),AES.MODE_ECB)
    if newNote=='' and note["note"]=='':
        return "Empty"
    encNote=aes.encrypt(pad(bytes(newNote.encode('utf-8')),16)).hex()
    if encNote==note["note"]:
        return "NoChange"
    coll.update_one({"hash":session["hash"]},{"$set":{"note":encNote}})
    return "Success"

@app.route("/delete",methods=["DELETE"])
def delete():
    try:
        coll.delete_one({"hash":session["hash"]})
        return "Success"
    except:
        return "Error"


if __name__=='__main__':
    app.run()