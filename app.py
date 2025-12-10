from repository import databaseSelectionHandler

from flask import Flask, render_template, request, session, redirect, url_for
from email_validator import validate_email, EmailNotValidError
import re
import bcrypt
app=Flask(__name__)

app.secret_key = bcrypt.gensalt()
connection = databaseSelectionHandler()

@app.route("/", methods=["GET"])
def Home():
    return render_template('Home.HTML')

@app.route("/booking", methods=["GET"])
def Booking():
    return render_template("Booking.HTML")

@app.route("/contact", methods=["GET"])
def Contact():
    return render_template("Contact.HTML")

@app.route("/Login", methods=["GET", "POST"])
def Login():
    if "user" in session:
        return redirect(url_for("Dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        email = email.lower()
        if not email or not password:
            return render_template("Login.HTML", message="Please fill in all fields.")
        if connection:
            successfulLogin = connection.extractUserDetails(password, email)
            if successfulLogin:
                session["user"] = email
                return redirect(url_for("Dashboard"))
            else:
                return render_template("Login.HTML", message="Invalid email or password.")
        else:
            return render_template("Login.HTML", message="Database connection error.")
    return render_template("Login.HTML")

@app.route("/Signup", methods=["GET", "POST"])
def Signup():
    if "user" in session:
        return redirect(url_for("Dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        email = email.lower()

        if not email or not password:
            return render_template("Signup.HTML", message="Please fill in all fields.")

        try:
            validate_email(email)
        except EmailNotValidError:
            return render_template("Signup.HTML", message="Invalid email!")

        passwordErrors = []
        if len(password) < 8:
            passwordErrors.append("at least 8 characters")
        if not re.search(r"[A-Z]", password):
            passwordErrors.append("one uppercase letter")
        if not re.search(r"[a-z]", password):
            passwordErrors.append("one lowercase letter")
        if not re.search(r"[0-9]", password):
            passwordErrors.append("one number")
        if not re.search(r"[^A-Za-z0-9]", password):
            passwordErrors.append("one special character")
        if passwordErrors:
            return render_template("Signup.HTML", message="Password must contain: " + ", ".join(passwordErrors) + ".")

        if connection:
            result = connection.insertUserDetails("", password, email)
            if result is False:
                return render_template("Signup.HTML", message="An account with this email already exists.")
            return render_template("Signup.HTML", message="Signup successful!")
        else:
            return render_template("Signup.HTML", message="Database connection error.")
    return render_template("Signup.HTML")

@app.route("/dashboard")
def Dashboard():
    if "user" not in session:
        return redirect(url_for("Login"))
    return render_template("Dashboard.HTML")

if __name__=="__main__": # Make's it so when you run the website and make changes, you don't have to restart it
    app.run(debug=True)