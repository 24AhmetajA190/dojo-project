from repository import databaseSelectionHandler

from flask import Flask, render_template, request, session, redirect, url_for
from email_validator import validate_email, EmailNotValidError
import re
import bcrypt

app = Flask(__name__)
app.secret_key = b"x"
connection = databaseSelectionHandler()

SESSIONS = [
    {
        "id": 1,
        "title": "Skegness Dojo",
        "description": "Descriptions.",
        "events": ["Event 1", "Event 2", "Event 3"]
    },
]

@app.route("/", methods=["GET"])
def Home():
    return render_template('Home.HTML')

@app.route("/booking", methods=["GET"])
def Booking():
    if not session.get("user"):
        return redirect(url_for("Login"))
    return render_template("Booking.HTML", sessions=SESSIONS)

@app.route("/contact", methods=["GET"])
def Contact():
    return render_template("Contact.HTML")

@app.route("/Signup", methods=["GET", "POST"])
def Signup():
    if session.get("user"):
        return redirect(url_for("Dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        if not email or not password:
            return render_template("Signup.HTML", message="Please fill in all fields.")
        try:
            validate_email(email)
        except EmailNotValidError:
            return render_template("Signup.HTML", message="Invalid email!")

        password_checks = [
            (len(password) >= 8, "at least 8 characters"),
            (re.search(r"[A-Z]", password), "one uppercase letter"),
            (re.search(r"[a-z]", password), "one lowercase letter"),
            (re.search(r"[0-9]", password), "one number"),
            (re.search(r"[^A-Za-z0-9]", password), "one special character")
        ]

        failed = [msg for check, msg in password_checks if not check]
        if failed:
            return render_template("Signup.HTML", message="Password must contain: " + ", ".join(failed) + ".")

        if not connection:
            return render_template("Signup.HTML", message="Database connection error.")
        result = connection.insertUserDetails("", password, email)
        if not result:
            return render_template("Signup.HTML", message="An account with this email already exists.")
        return render_template("Signup.HTML", message="Signup successful!")
    return render_template("Signup.HTML")

@app.route("/Login", methods=["GET", "POST"])
def Login():
    if session.get("user"):
        return redirect(url_for("Dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        if not email or not password:
            return render_template("Login.HTML", message="Please fill in all fields.")
        if not connection:
            return render_template("Login.HTML", message="Database connection error.")
        if connection.extractUserDetails(password, email):
            session["user"] = email
            return redirect(url_for("Dashboard"))
        return render_template("Login.HTML", message="Invalid email or password.")
    return render_template("Login.HTML")

@app.route("/session/<int:session_id>", methods=["GET", "POST"])
def SessionDetail(session_id):
    if not session.get("user"):
        return redirect(url_for("Login"))
    session_obj = next((s for s in SESSIONS if s["id"] == session_id), None)
    if not session_obj:
        return "Session not found", 404
    message = None
    if request.method == "POST":
        event_order = [
            request.form.get("event_order_0"),
            request.form.get("event_order_1"),
            request.form.get("event_order_2")
        ]
        if all(event_order) and connection:
            connection.insertBooking(session["user"], event_order, session_id)
            message = "Booking successful!"
        else:
            message = "Booking failed. Please try again."

    return render_template("SessionDetail.HTML", session_obj=session_obj, message=message)

@app.route("/dashboard", methods=["GET", "POST"])
def Dashboard():
    if not session.get("user"):
        return redirect(url_for("Login"))
    message = None
    if request.method == "POST":
        booking_id = request.form.get("cancel_booking_id")
        print(f"[DEBUG] Received cancel_booking_id: {booking_id}")
        print(f"[DEBUG] Current user for cancellation: {session.get('user')}")
        if booking_id and connection:
            try:
                booking_id_int = int(booking_id)
            except Exception:
                booking_id_int = booking_id
            print(f"[DEBUG] Attempting to cancel booking with id: {booking_id_int} for user: {session.get('user')}")
            success = connection.cancelBooking(booking_id_int, session["user"])
            print(f"[DEBUG] Cancel booking result: {success}")
            if success:
                message = "Booking cancelled."
            else:
                message = "Failed to cancel booking."
    bookings = connection.getBookingsForUser(session["user"]) if connection else []
    return render_template("Dashboard.HTML", bookings=bookings, message=message)

if __name__=="__main__": # Make's it so when you run the website and make changes, you don't have to restart it
    app.run(debug=True)