import json
import os
import uuid

from flask import (
Flask,
flash,
redirect,
render_template,
request,
session,
url_for,
send_from_directory
)

from werkzeug.security import (
generate_password_hash,
check_password_hash
)

from werkzeug.utils import secure_filename

from config import (
SECRET_KEY,
UPLOAD_FOLDER,
REPORT_FOLDER,
MAX_FILE_SIZE,
ALLOWED_EXTENSIONS
)

from database.database import (
initialize_database,
create_user,
get_user_by_username,
get_user_by_email,
get_user_by_id,
save_scan,
get_user_scans,
get_scan,
get_all_users,
get_all_scans,
get_statistics
)

from analyzers.url_analyzer import analyze_url
from analyzers.file_analyzer import analyze_file
from analyzers.risk_engine import calculate_risk

from auth.decorators import (
login_required,
admin_required
)

from services.threat_intelligence import (
lookup_file_hash
)

app = Flask(name)

app.secret_key = SECRET_KEY

app.config[
"MAX_CONTENT_LENGTH"
] = MAX_FILE_SIZE

os.makedirs(
UPLOAD_FOLDER,
exist_ok=True
)

os.makedirs(
REPORT_FOLDER,
exist_ok=True
)

initialize_database()

def allowed_file(filename):

return (
    "." in filename
    and
    filename.rsplit(
        ".",
        1
    )[1].lower()
    in ALLOWED_EXTENSIONS
)

def save_report(scan_id, result):

path = os.path.join(
    REPORT_FOLDER,
    f"scan_{scan_id}.json"
)

with open(
    path,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        result,
        file,
        indent=4,
        default=str
    )

@app.context_processor
def inject_user():

user = None

if "user_id" in session:

    user = get_user_by_id(
        session["user_id"]
    )

return {
    "current_user": user
}

@app.route("/")
@login_required
def index():

scans = get_user_scans(
    session["user_id"]
)

return render_template(
    "index.html",
    scans=scans[:5]
)

@app.route(
"/register",
methods=["GET", "POST"]
)
def register():

if request.method == "POST":

    username = request.form[
        "username"
    ].strip()

    email = request.form[
        "email"
    ].strip().lower()

    password = request.form[
        "password"
    ]

    if len(username) < 3:

        flash(
            "Username must contain at least 3 characters.",
            "error"
        )

        return redirect(
            url_for("register")
        )

    if len(password) < 8:

        flash(
            "Password must contain at least 8 characters.",
            "error"
        )

        return redirect(
            url_for("register")
        )

    if get_user_by_username(username):

        flash(
            "Username already exists.",
            "error"
        )

        return redirect(
            url_for("register")
        )

    if get_user_by_email(email):

        flash(
            "Email already exists.",
            "error"
        )

        return redirect(
            url_for("register")
        )

    password_hash = generate_password_hash(
        password
    )

    user_id = create_user(
        username,
        email,
        password_hash
    )

    if not user_id:

        flash(
            "Registration failed.",
            "error"
        )

        return redirect(
            url_for("register")
        )

    flash(
        "Registration successful. Please log in.",
        "success"
    )

    return redirect(
        url_for("login")
    )

return render_template(
    "register.html"
)

@app.route(
"/login",
methods=["GET", "POST"]
)
def login():

if request.method == "POST":

    username = request.form[
        "username"
    ].strip()

    password = request.form[
        "password"
    ]

    user = get_user_by_username(
        username
    )

    if (
        not user
        or
        not check_password_hash(
            user["password_hash"],
            password
        )
    ):

        flash(
            "Invalid username or password.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    session.clear()

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    return redirect(
        url_for("index")
    )

return render_template(
    "login.html"
)

@app.route("/logout")
def logout():

session.clear()

return redirect(
    url_for("login")
)

@app.route(
"/scan/url",
methods=["POST"]
)
@login_required
def scan_url():

url = request.form[
    "url"
].strip()

if not url:

    flash(
        "Enter a URL.",
        "error"
    )

    return redirect(
        url_for("index")
    )

result = analyze_url(url)

risk = calculate_risk(
    result["score"]
)

findings = "\n".join(
    result["findings"]
)

scan_id = save_scan(
    session["user_id"],
    "URL",
    result["url"],
    risk,
    result["score"],
    findings
)

result["scan_id"] = scan_id
result["risk_level"] = risk
result["scan_type"] = "URL"
result["target"] = result["url"]

save_report(
    scan_id,
    result
)

return render_template(
    "result.html",
    result=result
)

@app.route(
"/scan/file",
methods=["POST"]
)
@login_required
def scan_file():

if "file" not in request.files:

    flash(
        "No file selected.",
        "error"
    )

    return redirect(
        url_for("index")
    )

uploaded = request.files["file"]

if not uploaded.filename:

    flash(
        "No file selected.",
        "error"
    )

    return redirect(
        url_for("index")
    )

if not allowed_file(
    uploaded.filename
):

    flash(
        "File type is not allowed.",
        "error"
    )

    return redirect(
        url_for("index")
    )

filename = secure_filename(
    uploaded.filename
)

unique_name = (
    uuid.uuid4().hex
    + "_"
    + filename
)

filepath = os.path.join(
    UPLOAD_FOLDER,
    unique_name
)

uploaded.save(filepath)

try:

    result = analyze_file(
        filepath
    )

    intelligence = lookup_file_hash(
        result["hashes"]["sha256"]
    )

    result[
        "threat_intelligence"
    ] = intelligence

    if intelligence.get("found"):

        malicious = (
            intelligence
            .get("stats", {})
            .get("malicious", 0)
        )

        if malicious > 0:

            result["score"] = min(
                100,
                result["score"] + 50
            )

            result["findings"].append(
                "External threat intelligence "
                "reported malicious detections."
            )

    risk = calculate_risk(
        result["score"]
    )

    findings = "\n".join(
        result["findings"]
    )

    scan_id = save_scan(
        session["user_id"],
        "File",
        result["filename"],
        risk,
        result["score"],
        findings
    )

    result["scan_id"] = scan_id
    result["risk_level"] = risk
    result["scan_type"] = "File"
    result["target"] = result["filename"]

    save_report(
        scan_id,
        result
    )

    return render_template(
        "result.html",
        result=result
    )

finally:

    if os.path.exists(filepath):

        os.remove(filepath)

@app.route("/history")
@login_required
def history():

scans = get_user_scans(
    session["user_id"]
)

return render_template(
    "history.html",
    scans=scans
)

@app.route(
"/scan/int:scan_id"
)
@login_required
def scan_details(scan_id):

scan = get_scan(
    scan_id,
    session["user_id"]
)

if not scan:

    flash(
        "Scan not found.",
        "error"
    )

    return redirect(
        url_for("history")
    )

result = {
    "scan_id": scan["id"],
    "scan_type": scan["scan_type"],
    "target": scan["target"],
    "risk_level": scan["risk_level"],
    "score": scan["risk_score"],
    "findings":
        scan["findings"].split("\n")
}

return render_template(
    "result.html",
    result=result
)

@app.route(
"/report/int:scan_id"
)
@login_required
def report(scan_id):

scan = get_scan(
    scan_id,
    session["user_id"]
)

if not scan:

    flash(
        "Report not found.",
        "error"
    )

    return redirect(
        url_for("history")
    )

filename = (
    f"scan_{scan_id}.json"
)

return send_from_directory(
    REPORT_FOLDER,
    filename,
    as_attachment=True
)

@app.route("/admin")
@admin_required
def admin():

statistics = get_statistics()

users = get_all_users()

scans = get_all_scans()

return render_template(
    "admin.html",
    statistics=statistics,
    users=users,
    scans=scans
)

@app.errorhandler(413)
def file_too_large(error):

flash(
    "Maximum file size is 10 MB.",
    "error"
)

return redirect(
    url_for("index")
)

@app.errorhandler(404)
def page_not_found(error):

return render_template(
    "base.html"
), 404

if name == "main":

app.run(
    host="127.0.0.1",
    port=5000,
    debug=True
)
