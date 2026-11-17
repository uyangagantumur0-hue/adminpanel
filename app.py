import base64
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from functools import wraps
from urllib.parse import quote

import bcrypt
import requests
from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for


load_dotenv()
logging.basicConfig(level=logging.INFO)

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY", "").strip()
REQUEST_TIMEOUT = 10
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_ATTEMPT_WINDOW = 15 * 60

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
)

_attempts = defaultdict(deque)
_attempts_lock = threading.Lock()


def has_service_key():
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        return False
    if SUPABASE_SECRET_KEY.startswith("sb_secret_"):
        return True
    if SUPABASE_SECRET_KEY.startswith(("sb_publishable_", "sb_anon_")):
        return False

    parts = SUPABASE_SECRET_KEY.split(".")
    if len(parts) != 3:
        return False
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, json.JSONDecodeError):
        return False
    return claims.get("role") == "service_role"


def api_headers():
    return {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json",
    }


def supabase_request(method, table, **kwargs):
    headers = api_headers()
    headers.update(kwargs.pop("headers", {}))
    response = requests.request(
        method,
        f"{SUPABASE_URL}/rest/v1/{quote(table)}",
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        **kwargs,
    )
    response.raise_for_status()
    if response.content:
        return response.json()
    return None


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def check_csrf():
    submitted = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not hmac.compare_digest(submitted, expected):
        abort(400, description="Хүсэлтийн баталгаажуулалт амжилтгүй боллоо.")


def too_many_attempts(client_ip):
    now = time.monotonic()
    with _attempts_lock:
        attempts = _attempts[client_ip]
        while attempts and now - attempts[0] > LOGIN_ATTEMPT_WINDOW:
            attempts.popleft()
        return len(attempts) >= LOGIN_ATTEMPT_LIMIT


def record_failed_attempt(client_ip):
    now = time.monotonic()
    with _attempts_lock:
        attempts = _attempts[client_ip]
        while attempts and now - attempts[0] > LOGIN_ATTEMPT_WINDOW:
            attempts.popleft()
        attempts.append(now)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_email"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.get("/")
def home():
    if session.get("user_email"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    configured = has_service_key()
    if request.method == "POST":
        check_csrf()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "unknown"

        if not configured:
            error = "Supabase-ийн URL эсвэл нууц түлхүүр буруу байна."
        elif too_many_attempts(client_ip):
            error = "Олон удаа буруу оролдлоо. 15 минутын дараа дахин оролдоно уу."
        elif (
            not email
            or not password
            or len(email) > 320
            or len(password.encode("utf-8")) > 72
        ):
            record_failed_attempt(client_ip)
            error = "И-мэйл эсвэл нууц үг буруу байна."
        else:
            try:
                users = supabase_request(
                    "GET",
                    "users",
                    params={
                        "select": "email,password_hash",
                        "email": f"eq.{email}",
                        "limit": 1,
                    },
                )
                user = users[0] if users else None
                stored_hash = user.get("password_hash", "").encode("utf-8") if user else b""
                password_matches = bool(
                    user
                    and stored_hash.startswith(b"$2")
                    and bcrypt.checkpw(password.encode("utf-8"), stored_hash)
                )
                if password_matches:
                    session.clear()
                    session["user_email"] = user["email"]
                    csrf_token()
                    return redirect(url_for("dashboard"))
                record_failed_attempt(client_ip)
                error = "И-мэйл эсвэл нууц үг буруу байна."
            except (requests.RequestException, ValueError, TypeError):
                app.logger.exception("Supabase-аас хэрэглэгч шалгахад алдаа гарлаа.")
                error = "Өгөгдлийн сантай холбогдоход алдаа гарлаа. Тохиргоогоо шалгана уу."

    return render_template(
        "login.html",
        error=error,
        configured=configured,
        csrf_token=csrf_token(),
    )


@app.get("/dashboard")
@login_required
def dashboard():
    try:
        drafts = supabase_request(
            "GET",
            "content_drafts",
            params={
                "select": "id,title,content,status,created_at",
                "status": "eq.draft",
                "order": "created_at.desc",
            },
        )
    except (requests.RequestException, ValueError, TypeError):
        app.logger.exception("Ноорог пост татахад алдаа гарлаа.")
        return render_template(
            "dashboard.html",
            email=session["user_email"],
            drafts=[],
            error="Ноорог постуудыг татаж чадсангүй. Supabase-ийн тохиргоогоо шалгана уу.",
            csrf_token=csrf_token(),
            format_date=format_date,
            active_page="content",
        ), 502

    return render_template(
        "dashboard.html",
        email=session["user_email"],
        drafts=drafts,
        error=None,
        csrf_token=csrf_token(),
        format_date=format_date,
        active_page="content",
    )


@app.get("/bookings")
@login_required
def bookings():
    try:
        rows = supabase_request(
            "GET",
            "bookings",
            params={
                "select": "id,customer_name,customer_email,service_name,starts_at,notes,status",
                "order": "starts_at.asc",
            },
        )
    except (requests.RequestException, ValueError, TypeError):
        app.logger.exception("Захиалгуудыг татахад алдаа гарлаа.")
        return render_template(
            "bookings.html",
            email=session["user_email"],
            bookings=[],
            error="Захиалгуудыг татаж чадсангүй. Supabase-ийн тохиргоогоо шалгана уу.",
            csrf_token=csrf_token(),
            format_date=format_date,
            booking_status=booking_status,
            active_page="bookings",
        ), 502

    return render_template(
        "bookings.html",
        email=session["user_email"],
        bookings=rows,
        error=None,
        csrf_token=csrf_token(),
        format_date=format_date,
        booking_status=booking_status,
        active_page="bookings",
    )


@app.post("/bookings/<int:booking_id>/status")
@login_required
def update_booking_status(booking_id):
    check_csrf()
    next_status = {
        "approve": "confirmed",
        "reject": "cancelled",
    }.get(request.form.get("action", ""))
    if not next_status:
        abort(400, description="Захиалгын үйлдэл буруу байна.")

    try:
        updated = supabase_request(
            "PATCH",
            "bookings",
            params={
                "id": f"eq.{booking_id}",
                "status": "eq.pending",
                "select": "id",
            },
            headers={"Prefer": "return=representation"},
            json={"status": next_status},
        )
        if updated:
            message = (
                "Захиалгыг баталлаа."
                if next_status == "confirmed"
                else "Захиалгаас татгалзлаа."
            )
            flash(message, "success")
        else:
            flash(
                "Энэ захиалга хүлээгдэж буй төлөвт байхаа больсон байна. "
                "Жагсаалтыг дахин шалгана уу.",
                "notice",
            )
    except (requests.RequestException, ValueError, TypeError):
        app.logger.exception("Захиалгын төлөв шинэчлэхэд алдаа гарлаа.")
        flash("Захиалгын төлөвийг өөрчилж чадсангүй. Дахин оролдоно уу.", "error")

    return redirect(url_for("bookings"))


@app.get("/facebook")
@login_required
def facebook():
    return render_template(
        "coming_soon.html",
        email=session["user_email"],
        page_title="Facebook",
        csrf_token=csrf_token(),
        active_page="facebook",
    )


@app.get("/chat")
@login_required
def chat():
    return render_template(
        "coming_soon.html",
        email=session["user_email"],
        page_title="Чат",
        csrf_token=csrf_token(),
        active_page="chat",
    )


@app.post("/logout")
@login_required
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("login"))


def format_date(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%Y-%m-%d %H:%M")
    except (AttributeError, TypeError, ValueError):
        return value or ""


def booking_status(value):
    labels = {
        "pending": "Хүлээгдэж буй",
        "confirmed": "Баталгаажсан",
        "cancelled": "Цуцлагдсан",
        "completed": "Дууссан",
    }
    return labels.get(value, value or "Тодорхойгүй")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
