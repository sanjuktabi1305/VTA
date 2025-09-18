import os
import hashlib
import sqlite3

# Hardcoded secrets
API_KEY = "12345-ABCDE"
password = "superSecret"

def insecure_sql(user_input, user_id):
    # SQL Injection via string concatenation
    query = "SELECT * FROM accounts WHERE name='" + user_input + "' AND id=" + str(user_id)
    return query

def dangerous_code(code_str):
    # Arbitrary code execution
    eval(code_str)
    exec("print('Executed dangerous code')")

def delete_stuff(path):
    # Command injection
    os.system("rm -rf " + path)

def weak_hash(data):
    # Using weak hashing (MD5)
    return hashlib.md5(data.encode()).hexdigest()

def insecure_file_write(content):
    f = open("output.txt", "w")
    f.write(content)  # no validation
    f.close()

def hardcoded_db_password():
    db_pass = "root123"   # another hardcoded secret
    return db_pass
