import os
import secrets
from uuid import uuid4
from datetime import datetime, timedelta
import traceback

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_from_directory, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import inspect

# ---------------------------
# Config & setup
# ---------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {
    "pdf","png","jpg","jpeg","gif","txt","csv","zip","doc","docx",
    "ppt","pptx","xls","xlsx","json","mp4","mp3","md"
}

# S3 (optional)
S3_BUCKET = os.getenv("S3_BUCKET", "")
S3_PREFIX = os.getenv("S3_PREFIX", "uploads/")
S3_REGION = os.getenv("AWS_REGION", "us-east-1")
USE_S3 = bool(S3_BUCKET)

if USE_S3:
    import boto3
    s3 = boto3.client("s3", region_name=S3_REGION)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "campus_cloud.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB
app.config["TEMPLATES_AUTO_RELOAD"] = False
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = timedelta(days=30)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


# ---------------------------
# Models
# ---------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    files = db.relationship("File", backref="owner", lazy=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    stored_name = db.Column(db.String(256), nullable=False)   # path/key on storage
    original_name = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    size_bytes = db.Column(db.Integer, default=0)
    share_token = db.Column(db.String(64), unique=True, nullable=True)  # if set, public link


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------------
# Helpers
# ---------------------------
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def ensure_db():
    """Create tables once (safe for Flask 3.x and multiple restarts)."""
    with app.app_context():
        insp = inspect(db.engine)
        try:
            need_create = (not insp.has_table("user")) or (not insp.has_table("file"))
        except Exception:
            need_create = True
        if need_create:
            db.create_all()


ensure_db()


def _upload_to_storage(file_storage, stored_name: str):
    """Save to S3 (private) or local uploads/."""
    if USE_S3:
        key = f"{S3_PREFIX}{stored_name}"
        file_storage.seek(0)
        # private upload (no public ACL)
        s3.upload_fileobj(file_storage, S3_BUCKET, key, ExtraArgs={"ACL": "private"})
    else:
        path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
        # ensure nested dirs exist if stored_name contains user id folder
        os.makedirs(os.path.dirname(path), exist_ok=True)
        file_storage.seek(0)
        file_storage.save(path)


def _delete_from_storage(stored_name: str):
    if USE_S3:
        key = f"{S3_PREFIX}{stored_name}"
        try:
            s3.delete_object(Bucket=S3_BUCKET, Key=key)
        except Exception:
            pass
    else:
        try:
            os.remove(os.path.join(app.config["UPLOAD_FOLDER"], stored_name))
        except OSError:
            pass


def _generate_presigned_download(stored_name: str, download_name: str, minutes: int = 30) -> str:
    if USE_S3:
        key = f"{S3_PREFIX}{stored_name}"
        return s3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": S3_BUCKET,
                "Key": key,
                "ResponseContentDisposition": f"attachment; filename={download_name}",
            },
            ExpiresIn=int(minutes * 60),
        )
    else:
        return url_for("local_download", stored_name=stored_name, _external=True)


# ---------------------------
# Routes
# ---------------------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
            return redirect(url_for("register"))
        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    files = File.query.filter_by(user_id=current_user.id).order_by(File.created_at.desc()).all()
    return render_template("dashboard.html", files=files, use_s3=USE_S3)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    try:
        if "file" not in request.files:
            flash("No file part.", "error")
            return redirect(url_for("dashboard"))

        f = request.files["file"]
        if not f or f.filename == "":
            flash("No selected file.", "error")
            return redirect(url_for("dashboard"))

        if not allowed_file(f.filename):
            flash("File type not allowed.", "error")
            return redirect(url_for("dashboard"))

        original_name = secure_filename(f.filename)

        # Compute size safely
        f.stream.seek(0, os.SEEK_END)
        size_bytes = f.stream.tell()
        f.stream.seek(0)

        # Unique stored name (keep user id for neat per-user foldering)
        stored_name = f"{current_user.id}/{uuid4().hex}_{original_name}"

        # Save to S3 or local
        _upload_to_storage(f, stored_name)

        # Record in DB
        rec = File(
            user_id=current_user.id,
            stored_name=stored_name,
            original_name=original_name,
            size_bytes=size_bytes,
        )
        db.session.add(rec)
        db.session.commit()

        kb = round(size_bytes / 1024, 1)
        flash(f"Uploaded {original_name} ({kb} KB).", "success")
        return redirect(url_for("dashboard"))

    except Exception as e:
        print("UPLOAD_ERROR:", repr(e))
        traceback.print_exc()
        flash("Upload failed. Please try again.", "error")
        return redirect(url_for("dashboard"))


@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    rec = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    url = _generate_presigned_download(rec.stored_name, rec.original_name, minutes=30)
    return redirect(url)


@app.route("/local/<stored_name>")
@login_required
def local_download(stored_name):
    if USE_S3:
        abort(404)
    return send_from_directory(app.config["UPLOAD_FOLDER"], stored_name, as_attachment=True)


@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete(file_id):
    rec = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    _delete_from_storage(rec.stored_name)
    db.session.delete(rec)
    db.session.commit()
    flash("File deleted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
def share(file_id):
    rec = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    if not rec.share_token:
        rec.share_token = secrets.token_urlsafe(16)
        db.session.commit()
    flash("Public link created.", "success")
    return redirect(url_for("dashboard"))


@app.route("/unshare/<int:file_id>", methods=["POST"])
@login_required
def unshare(file_id):
    rec = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    rec.share_token = None
    db.session.commit()
    flash("Public link disabled.", "success")
    return redirect(url_for("dashboard"))


@app.route("/s/<token>")
def public_download(token):
    rec = File.query.filter_by(share_token=token).first()
    if not rec:
        abort(404)
    url = _generate_presigned_download(rec.stored_name, rec.original_name, minutes=15)
    return redirect(url)


if __name__ == "__main__":
    # Local dev only; on Render use gunicorn (set workers=1 for SQLite)
    app.run(host="0.0.0.0", port=5000, debug=True)
