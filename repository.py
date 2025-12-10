##################################################
# Imports and Setup
##################################################

import json
import psycopg2
import os
import bcrypt
import sqlite3
from random_username.generate import generate_username

##################################################
# Postgres
##################################################

class postgresHandler():
    def __init__(self, connectionDetails, host, userName, password, dbName, port):
        self.connectionDetails = connectionDetails
        self.host = host
        self.userName = userName
        self.password = password
        self.dbName = dbName
        self.port = port

    def dbConnect(self):
        print(f"[DEBUG] Connecting to database: {self.dbName} as user: {self.userName} on host: {self.host} port: {self.port}")
        connect = psycopg2.connect(
            dbname=self.dbName,
            user=self.userName,
            password=self.password,
            host=self.host,
            port=self.port
        )
        return connect

    def dbInitializeCheck(self):
        try:
            with self.dbConnect() as connect:
                with connect.cursor() as cursor:
                    cursor.execute('''
CREATE TABLE IF NOT EXISTS userDetailsTable (
    id SERIAL PRIMARY KEY,
    username TEXT,
    password TEXT,
    email TEXT
);
                    ''')
                    print("Checked for userDetailsTable")
                    connect.commit()
        except Exception as e:
            print(f"[ERROR] dbInitializeCheck failed: {e}")

    def insertUserDetails(self, username, password, email):
        with self.dbConnect() as connect:
            with connect.cursor() as cursor:
                cursor.execute(
                    "SELECT 1 FROM userDetailsTable WHERE LOWER(email) = LOWER(%s);",
                    (email,)
                )
                if cursor.fetchone():
                    print("Email already exists.")
                    return False
                sqlString = """INSERT INTO userDetailsTable (username, password, email)
VALUES (%s, %s, %s)"""
                if not username:
                    username = generate_username(1)[0]
                passwordEncryption = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                passwordEncryption = passwordEncryption.strip()
                print(f"{username} {passwordEncryption} {email}")
                cursor.execute(sqlString, (username, passwordEncryption, email))
                connect.commit()
                return True

    def extractUserDetails(self, password, email):
        with self.dbConnect() as connect:
            with connect.cursor() as cursor:
                sqlQuery = """
SELECT password
FROM userDetailsTable
WHERE LOWER(email) = LOWER(%s);
                """
                cursor.execute(sqlQuery, (email,))
                userData = cursor.fetchone()
                
                if userData:
                    storedHashedPassword = userData[0]
                    if isinstance(storedHashedPassword, str):
                        storedHashedPassword = storedHashedPassword.strip()
                        if not storedHashedPassword.startswith("$2"):
                            print("Invalid bcrypt hash format in database.")
                            return False
                        storedHashedPassword = storedHashedPassword.encode('utf-8')
                    try:
                        isPasswordCorrect = bcrypt.checkpw(password.encode('utf-8'), storedHashedPassword)
                    except ValueError as e:
                        print(f"bcrypt error: {e}")
                        return False
                    if isPasswordCorrect:
                        print("Login successful.")
                        return True
                    else:
                        print("Incorrect password.")
                        return False
                else:
                    print("Email not found.")
                    return False

##################################################
# SQLite
##################################################

class sqliteHandler():
    def __init__(self, dbFile="userdetails.db"):
        self.dbFile = dbFile

    def dbConnect(self):
        db_exists = os.path.exists(self.dbFile)
        connect = sqlite3.connect(self.dbFile)

        if not db_exists:
            print(f"[INFO] Created new SQLite database file: {self.dbFile}")
        else:
            print(f"[INFO] Opened existing SQLite database file: {self.dbFile}")

        return connect

    def dbInitializeCheck(self):
        try:
            with self.dbConnect() as connect:
                cursor = connect.cursor()
                cursor.execute('''
CREATE TABLE IF NOT EXISTS userDetailsTable (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    email TEXT
);
                ''')
                print("Checked for userDetailsTable (SQLite)")
                connect.commit()
        except Exception as e:
            print(f"[ERROR] dbInitializeCheck failed: {e}")

    def insertUserDetails(self, username, password, email):
        with self.dbConnect() as connect:
            cursor = connect.cursor()
            cursor.execute(
                "SELECT email FROM userDetailsTable WHERE LOWER(email) = LOWER(?);",
                (email,)
            )
            if cursor.fetchone():
                print("Email already exists.")
                return False
            sqlString = """INSERT INTO userDetailsTable (username, password, email)
VALUES (?, ?, ?)"""
            if not username:
                username = generate_username(1)[0]
            passwordEncryption = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            passwordEncryption = passwordEncryption.strip()
            print(f"{username} {passwordEncryption} {email}")
            cursor.execute(sqlString, (username, passwordEncryption, email))
            connect.commit()
            return True

    def extractUserDetails(self, password, email):
        with self.dbConnect() as connect:
            cursor = connect.cursor()
            sqlQuery = """
SELECT password
FROM userDetailsTable
WHERE LOWER(email) = LOWER(?);
            """
            cursor.execute(sqlQuery, (email,))
            userData = cursor.fetchone()
            
        if not userData:
            print("Email not found.")
            return False

        storedHashedPassword = userData[0]

        if isinstance(storedHashedPassword, str):
            storedHashedPassword = storedHashedPassword.strip()
            if not storedHashedPassword.startswith("$2"):
                print("Invalid bcrypt hash format in database.")
                return False
            storedHashedPassword = storedHashedPassword.encode('utf-8')

        try:
            if bcrypt.checkpw(password.encode('utf-8'), storedHashedPassword):
                print("Login successful.")
                return True
            else:
                print("Incorrect password.")
                return False
        except ValueError as e:
            print(f"bcrypt error: {e}")
            return False


##################################################
# Database Selection
##################################################

def databaseSelectionHandler(connectionDetailsFilePath="connectionDetails.json", programInstance=os.path.basename(__file__)):
    """
    Within the function `databaseSelectionHandler` there is a variable declared under the name `databaseSelected`.
    This variable dictates the database that the results of any match are being written into:
    1) Postgres
    2) SQLite
    If `databaseSelected` is not set to any of the values referred to above, then the program will automatically
    resort to DBeaver as its database. As of now, there is no option to modify this within the gradio application
    itself.
    """

    databaseSelected = 2

    try:
        with open(connectionDetailsFilePath, "r") as file:
            connectionDetails = json.load(file)
    except FileNotFoundError:
        connectionDetails = {}

    if databaseSelected == 1:
        try:
            postgresConnector = connectionDetails["postgres"]
            connection = postgresHandler(
                connectionDetails=postgresConnector,
                host=postgresConnector["host"],
                userName=postgresConnector["user"],
                password=postgresConnector["password"],
                dbName=postgresConnector["dbname"],
                port=postgresConnector["port"]
            )
            print(f"{programInstance}: Valid Postgres connection details.")
            try:
                connection.dbInitializeCheck()
                return connection
            except Exception as e:
                print(f"DB initialization failed: {e}")
                return None
        except (KeyError, TypeError) as e:
            print(f"{programInstance}: Invalid Postgres connection details. {e}")
            return None
    elif databaseSelected == 2:
        try:
            connection = sqliteHandler()
            print(f"{programInstance}: Using SQLite database file: {connection.dbFile}")
            try:
                connection.dbInitializeCheck()
                return connection
            except Exception as e:
                print(f"DB initialization failed: {e}")
                return None
        except Exception as e:
            print(f"{programInstance}: SQLite handler error: {e}")
            return None
    print("No valid database connection. Using false handler.")

if __name__ == "__main__":
    print("If you're seeing this you didn't load 'app.py'")
    connection = databaseSelectionHandler()