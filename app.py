import os
import io
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Optional S3
USE_S3 = bool(os.environ.get("S3_BUCKET"))
S3_BUCKET = os.environ.get("S3_BUCKET","")
S3_PREFIX = os.environ.get("S3_PREFIX","uploads/")  # folder/prefix inside the bucket
S3_REGION = os.environ.get("AWS_REGION","us-east-1")

if USE_S3:
    import boto3
    s3 = boto3.client("s3", region_name=S3_REGION)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = set(["txt","pdf","png","jpg","jpeg","gif","doc","docx","ppt","pptx","xlsx","csv","zip","tar","gz","mp4","mp3","md"])

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY","dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "campus_cloud.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    files = db.relationship("File", backref="owner", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    stored_name = db.Column(db.String(256), nullable=False)  # key on S3 or filename locally
    original_name = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    size_bytes = db.Column(db.Integer, default=0)
    share_token = db.Column(db.String(64), unique=True, nullable=True)  # if set, public link available

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.before_first_request
def init_db():
    db.create_all()

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        if not email or not password:
            flash("Email and password are required.","error")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Email already registered.","error")
            return redirect(url_for("register"))
        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.","success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Welcome back!","success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.","error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.","success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    files = File.query.filter_by(user_id=current_user.id).order_by(File.created_at.desc()).all()
    return render_template("dashboard.html", files=files, use_s3=USE_S3)

def _upload_to_storage(file_storage, stored_name):
    if USE_S3:
        key = f"{S3_PREFIX}{stored_name}"
        file_storage.seek(0)
        s3.upload_fileobj(file_storage, S3_BUCKET, key, ExtraArgs={"ACL":"private"})
    else:
        path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
        file_storage.save(path)

def _delete_from_storage(stored_name):
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

def _generate_presigned_download(stored_name, download_name, minutes=30):
    if USE_S3:
        key = f"{S3_PREFIX}{stored_name}"
        return s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": key, "ResponseContentDisposition": f"attachment; filename={download_name}"},
            ExpiresIn=int(minutes*60),
        )
    else:
        # local download route
        return url_for("local_download", stored_name=stored_name, _external=True)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        flash("No file part.","error")
        return redirect(url_for("dashboard"))
    file = request.files["file"]
    if file.filename == "":
        flash("No selected file.","error")
        return redirect(url_for("dashboard"))
    if file and allowed_file(file.filename):
        original_name = secure_filename(file.filename)
        stored_name = secrets.token_hex(16) + "_" + original_name
        # Upload to storage
        _upload_to_storage(file, stored_name)
        size_bytes = file.seek(0, os.SEEK_END) or 0
        rec = File(user_id=current_user.id, stored_name=stored_name, original_name=original_name, size_bytes=size_bytes)
        db.session.add(rec)
        db.session.commit()
        flash("File uploaded.","success")
    else:
        flash("File type not allowed.","error")
    return redirect(url_for("dashboard"))

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    rec = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    url = _generate_presigned_download(rec.stored_name, rec.original_name, minutes=30)
    return redirect(url)

# Local-only download path
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
    flash("File deleted.","success")
    return redirect(url_for("dashboard"))

@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
def share(file_id):
    rec = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    if not rec.share_token:
        rec.share_token = secrets.token_urlsafe(16)
        db.session.commit()
    flash("Public link created.","success")
    return redirect(url_for("dashboard"))

@app.route("/unshare/<int:file_id>", methods=["POST"])
@login_required
def unshare(file_id):
    rec = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    rec.share_token = None
    db.session.commit()
    flash("Public link disabled.","success")
    return redirect(url_for("dashboard"))

@app.route("/s/<token>")
def public_download(token):
    rec = File.query.filter_by(share_token=token).first()
    if not rec:
        abort(404)
    # issue a short-lived presigned URL (or local)
    url = _generate_presigned_download(rec.stored_name, rec.original_name, minutes=15)
    return redirect(url)

if __name__ == "__main__":
    app.run(debug=True)
