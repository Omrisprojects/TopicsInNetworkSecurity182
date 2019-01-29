import sqlite3
import os
import json
import hashlib
import server

def create_db():
    db_existed = os.path.isfile('virus_signatures.db')
    with sqlite3.connect('virus_signatures.db') as dbcon:
        cursor = dbcon.cursor()
        if not db_existed:
            cursor.execute("""CREATE TABLE Signatures (
                            signature TEXT PRIMARY KEY NOT NULL,
                            virus_name TEXT NOT NULL)""")
    load_signatures_to_db()

def search_in_db(virus_sig):
    with sqlite3.connect('virus_signatures.db') as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT * FROM Signatures WHERE signature = (?)""", (virus_sig,))
        return cursor.fetchall()

def load_signatures_to_db():
    list_of_viruses = os.listdir("./viruses/")
    with sqlite3.connect('virus_signatures.db') as dbcon:
        cursor = dbcon.cursor()
        for virus in list_of_viruses:
            # print server.MD5_checksum("./viruses/" + virus)
            # print virus
            cursor.execute("""INSERT INTO Signatures (signature, virus_name) VALUES(?, ?)""", (server.MD5_checksum("./viruses/" + virus), virus))
    return cursor.lastrowid
