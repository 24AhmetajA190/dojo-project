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
        return psycopg2.connect(
            dbname=self.dbName,
            user=self.userName,
            password=self.password,
            host=self.host,
            port=self.port
        )

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
                    cursor.execute('''
CREATE TABLE IF NOT EXISTS bookingTable (
    id SERIAL PRIMARY KEY,
    user_email TEXT NOT NULL,
    session_id INTEGER NOT NULL,
    event1 TEXT NOT NULL,
    event2 TEXT NOT NULL,
    event3 TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
                    ''')
                    connect.commit()
        except Exception:
            pass

    def insertUserDetails(self, username, password, email):
        with self.dbConnect() as connect:
            with connect.cursor() as cursor:
                cursor.execute(
                    "SELECT 1 FROM userDetailsTable WHERE LOWER(email) = LOWER(%s);",
                    (email,)
                )
                if cursor.fetchone():
                    return False
                sqlString = """INSERT INTO userDetailsTable (username, password, email)
VALUES (%s, %s, %s)"""
                if not username:
                    username = generate_username(1)[0]
                passwordEncryption = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8').strip()
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
                if not userData:
                    return False
                storedHashedPassword = userData[0]
                if isinstance(storedHashedPassword, str):
                    storedHashedPassword = storedHashedPassword.strip()
                    if not storedHashedPassword.startswith("$2"):
                        return False
                    storedHashedPassword = storedHashedPassword.encode('utf-8')
                try:
                    return bcrypt.checkpw(password.encode('utf-8'), storedHashedPassword)
                except ValueError:
                    return False

    def insertBooking(self, user_email, event_order, session_id):
        with self.dbConnect() as connect:
            with connect.cursor() as cursor:
                # Check if booking already exists for this user and session
                check_sql = '''SELECT 1 FROM bookingTable WHERE user_email = %s AND session_id = %s'''
                cursor.execute(check_sql, (user_email, session_id))
                if cursor.fetchone():
                    return False  # Booking already exists
                sql = '''INSERT INTO bookingTable (user_email, session_id, event1, event2, event3) VALUES (%s, %s, %s, %s, %s)'''
                cursor.execute(sql, (user_email, session_id, event_order[0], event_order[1], event_order[2]))
                connect.commit()
                return True

    def getBookingsForUser(self, user_email):
        with self.dbConnect() as connect:
            with connect.cursor() as cursor:
                sql = '''SELECT id, event1, event2, event3, created_at FROM bookingTable WHERE user_email = %s ORDER BY created_at DESC'''
                cursor.execute(sql, (user_email,))
                return cursor.fetchall()

    def cancelBooking(self, booking_id, user_email):
        with self.dbConnect() as connect:
            with connect.cursor() as cursor:
                sql = '''DELETE FROM bookingTable WHERE id = %s AND user_email = %s'''
                cursor.execute(sql, (booking_id, user_email))
                connect.commit()
                return cursor.rowcount > 0

##################################################
# SQLite
##################################################

class sqliteHandler():
    def __init__(self, dbFile="userdetails.db"):
        self.dbFile = dbFile

    def dbConnect(self):
        return sqlite3.connect(self.dbFile)

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
                cursor.execute('''
CREATE TABLE IF NOT EXISTS bookingTable (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    session_id INTEGER NOT NULL,
    event1 TEXT NOT NULL,
    event2 TEXT NOT NULL,
    event3 TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
                    ''')
                connect.commit()
        except Exception:
            pass

    def insertUserDetails(self, username, password, email):
        with self.dbConnect() as connect:
            cursor = connect.cursor()
            cursor.execute(
                "SELECT email FROM userDetailsTable WHERE LOWER(email) = LOWER(?);",
                (email,)
            )
            if cursor.fetchone():
                return False
            sqlString = """INSERT INTO userDetailsTable (username, password, email)
VALUES (?, ?, ?)"""
            if not username:
                username = generate_username(1)[0]
            passwordEncryption = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8').strip()
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
            return False

        storedHashedPassword = userData[0]
        if isinstance(storedHashedPassword, str):
            storedHashedPassword = storedHashedPassword.strip()
            if not storedHashedPassword.startswith("$2"):
                return False
            storedHashedPassword = storedHashedPassword.encode('utf-8')

        try:
            return bcrypt.checkpw(password.encode('utf-8'), storedHashedPassword)
        except ValueError:
            return False

    def insertBooking(self, user_email, event_order, session_id):
        with self.dbConnect() as connect:
            cursor = connect.cursor()
            # Check if booking already exists for this user and session
            check_sql = '''SELECT 1 FROM bookingTable WHERE user_email = ? AND session_id = ?'''
            cursor.execute(check_sql, (user_email, session_id))
            if cursor.fetchone():
                return False  # Booking already exists
            sql = '''INSERT INTO bookingTable (user_email, session_id, event1, event2, event3) VALUES (?, ?, ?, ?, ?)'''
            cursor.execute(sql, (user_email, session_id, event_order[0], event_order[1], event_order[2]))
            connect.commit()
            return True

    def getBookingsForUser(self, user_email):
        with self.dbConnect() as connect:
            cursor = connect.cursor()
            sql = '''SELECT id, event1, event2, event3, created_at FROM bookingTable WHERE user_email = ? ORDER BY created_at DESC'''
            cursor.execute(sql, (user_email,))
            return cursor.fetchall()

    def cancelBooking(self, booking_id, user_email):
        with self.dbConnect() as connect:
            cursor = connect.cursor()
            sql = '''DELETE FROM bookingTable WHERE id = ? AND user_email = ?'''
            cursor.execute(sql, (booking_id, user_email))
            connect.commit()
            return cursor.rowcount > 0


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
            try:
                connection.dbInitializeCheck()
                return connection
            except Exception:
                return None
        except (KeyError, TypeError):
            return None
    elif databaseSelected == 2:
        try:
            connection = sqliteHandler()
            try:
                connection.dbInitializeCheck()
                return connection
            except Exception:
                return None
        except Exception:
            return None
    return None

if __name__ == "__main__":
    print("If you're seeing this you didn't load 'app.py'")
    connection = databaseSelectionHandler()