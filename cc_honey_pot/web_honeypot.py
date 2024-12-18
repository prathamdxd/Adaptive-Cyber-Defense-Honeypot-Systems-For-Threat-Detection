from flask import Flask, request, jsonify, render_template, redirect, url_for
import datetime
import os

app = Flask(__name__)
app.debug = True 
USERNAME = "username"
PASSWORD = "password"

LOG_FILE = "honeypot_logs.txt"


def log_event(event_type, details):
    """Log events to a file with a timestamp and IP address."""
    with open(LOG_FILE, "a") as file:
        log_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_address = request.remote_addr or "Unknown IP"
        log_message = f"[{log_time}] [IP: {ip_address}] {event_type}: {details}\n"
        file.write(log_message)


@app.route("/")
def home():
    """Serve the login page."""
    return render_template("dashboard.html")  


@app.route("/login", methods=["POST"])
def login():
    ip_address = request.remote_addr
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    correct_username = "username"
    correct_password = "password"

    if username == correct_username and password == correct_password:
        log_event(ip_address, "Successful Login", f"Username: {username}")
        return jsonify({"message": "Login successful"}), 200
    else:
        log_event(ip_address, "Failed Login Attempt", f"Username: {username}, Password: {password}")
        return jsonify({"message": "Login failed"}), 401


@app.route("/dashboard")
def dashboard():
    """Serve the main dashboard."""
    return render_template("dashboard.html") 


@app.route("/log-action", methods=["POST"])
def log_action():
    """Log user actions on the website."""
    data = request.json
    action_type = data.get("action_type")
    details = data.get("details", "")
    log_event("User Action", f"Action Type: {action_type}, Details: {details}")
    return jsonify({"status": True})


if __name__ == "__main__":
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as file:
            file.write("Honeypot Logs\n")
            file.write("=" * 50 + "\n")
    app.run(debug=True, host="0.0.0.0")
