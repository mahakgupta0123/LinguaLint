# app.py
import os
import json
import hmac
import hashlib
import secrets
import requests
import logging
import sys
import traceback
import eventlet
eventlet.monkey_patch()

from datetime import datetime
from flask import Flask, request, jsonify, redirect, make_response
from flask_cors import CORS
from flask_socketio import SocketIO, join_room
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

# ------------ APP CONFIG ------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))

GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5173')
APP_URL = os.getenv('APP_URL')   # Your NGROK domain
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', secrets.token_hex(32))

DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'user.json')
REVIEWS_FILE = os.path.join(DATA_DIR, 'review.json')

os.makedirs(DATA_DIR, exist_ok=True)
for f in [USERS_FILE, REVIEWS_FILE]:
    if not os.path.exists(f):
        with open(f, 'w') as file:
            json.dump({}, file)

# Accept both the FRONTEND_URL and plain http://localhost (nginx root)
ALLOWED_ORIGINS = [FRONTEND_URL, "http://localhost", "http://localhost:80"]

CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS, async_mode='eventlet')


logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("LinguaLintBackend")


# ------------ UTILS ------------
def load_json(path):
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except:
        return {}


def save_json(path, data):
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except:
        return False


def generate_id(prefix):
    return f"{prefix}_{secrets.token_hex(8)}"


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('gh_token')
        if not token:
            return jsonify({'logged_in': False}), 401

        users = load_json(USERS_FILE)
        user = next((u for u in users.values() if u.get('token') == token), None)

        if not user:
            return jsonify({'logged_in': False}), 401

        request.user = user
        return f(*args, **kwargs)
    return decorated


def verify_webhook_signature(payload_body, signature_header):
    if not signature_header:
        return False

    mac = hmac.new(WEBHOOK_SECRET.encode(), msg=payload_body, digestmod=hashlib.sha256)
    return hmac.compare_digest("sha256=" + mac.hexdigest(), signature_header)


# ------------ GITHUB OAUTH ------------
@app.route("/api/auth/github")
def github_login():
    state = secrets.token_hex(16)

    resp = make_response(redirect(
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&scope=repo%20read:user"
        f"&redirect_uri={APP_URL}/api/auth/github/callback"
        f"&state={state}"
    ))

    resp.set_cookie("oauth_state", state, httponly=True, samesite="Lax", max_age=600)
    return resp


@app.route("/api/auth/github/callback")
def github_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    stored_state = request.cookies.get("oauth_state")

    if not code:
        return "No code received", 400

    if not state or stored_state != state:
        return "Invalid OAuth state", 400

    # Exchange code for token
    token_resp = requests.post(
        "https://github.com/login/oauth/access_token",
        headers={"Accept": "application/json"},
        data={
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": f"{APP_URL}/api/auth/github/callback"
        }
    ).json()

    gh_token = token_resp.get("access_token")
    if not gh_token:
        return "OAuth failed", 500

    # Fetch GitHub user
    user_resp = requests.get(
        "https://api.github.com/user",
        headers={"Authorization": f"token {gh_token}"}
    ).json()

    username = user_resp.get("login")
    avatar = user_resp.get("avatar_url")

    # Save user in DB
    users = load_json(USERS_FILE)
    users[username] = {
        "username": username,
        "avatar": avatar,
        "token": gh_token,
        "repos": []
    }
    save_json(USERS_FILE, users)

    # Set cookie and redirect to frontend
    resp = make_response(redirect(f"{FRONTEND_URL}/dashboard"))
    resp.set_cookie("gh_token", gh_token, httponly=True, samesite="Lax")
    return resp


# ------------ USER DATA ------------
@app.route("/api/me")
def get_user():
    token = request.cookies.get('gh_token')
    users = load_json(USERS_FILE)

    user = next((u for u in users.values() if u.get("token") == token), None)

    if not user:
        return jsonify({"logged_in": False})

    return jsonify({
        "logged_in": True,
        "username": user["username"],
        "avatar": user["avatar"],
        "repos_count": len(user["repos"])
    })


# ------------ REPOS ------------
@app.route("/api/repos")
@require_auth
def get_repos():
    resp = requests.get(
        "https://api.github.com/user/repos",
        headers={"Authorization": f"token {request.user['token']}"}
    )

    repos = resp.json()
    formatted = [
        {
            "id": r["id"],
            "name": r["name"],
            "full_name": r["full_name"],
            "language": r.get("language")
        }
        for r in repos
    ]

    # Save to user
    users = load_json(USERS_FILE)
    users[request.user["username"]]["repos"] = formatted
    save_json(USERS_FILE, users)

    return jsonify(formatted)


# ------------ REVIEWS ------------
@app.route("/api/reviews")
@require_auth
def get_reviews():
    return jsonify(list(load_json(REVIEWS_FILE).values()))


# ------------ ANALYTICS ------------
@app.route("/api/analytics")
@require_auth
def get_analytics():
    reviews = load_json(REVIEWS_FILE)
    analytics = {
        "total_reviews": len(reviews),
        "issues_by_severity": {},
        "issues_by_type": {},
        "reviews_per_repo": {}
    }

    for r in reviews.values():
        for issue in r.get("issues", []):
            analytics["issues_by_severity"][issue["severity"]] = \
                analytics["issues_by_severity"].get(issue["severity"], 0) + 1

            analytics["issues_by_type"][issue["type"]] = \
                analytics["issues_by_type"].get(issue["type"], 0) + 1

        repo = r["repo"]
        analytics["reviews_per_repo"][repo] = \
            analytics["reviews_per_repo"].get(repo, 0) + 1

    return jsonify(analytics)


# ------------ WEBHOOK ------------
@app.route("/webhook", methods=["POST"])
def webhook():
    signature = request.headers.get("X-Hub-Signature-256")

    if not verify_webhook_signature(request.get_data(), signature):
        return jsonify({"error": "Invalid signature"}), 401

    payload = request.get_json()
    pr = payload.get("pull_request", {})
    repo_name = payload.get("repository", {}).get("full_name")

    review = {
        "id": generate_id("review"),
        "repo": repo_name,
        "pr_number": pr.get("number"),
        "title": pr.get("title"),
        "status": "completed",
        "timestamp": datetime.utcnow().isoformat(),
        "issues": [],
        "suggestions": [],
        "votes": {"upvotes": 0, "downvotes": 0}
    }

    reviews = load_json(REVIEWS_FILE)
    reviews[review["id"]] = review
    save_json(REVIEWS_FILE, reviews)

    # Broadcast to all users
    users = load_json(USERS_FILE)
    for u in users.values():
        socketio.emit("new_review", review, room=f"user:{u['username']}")

    return jsonify({"message": "Webhook processed"}), 200


# ------------ SOCKET.IO ------------
@socketio.on("connect")
def connected():
    logger.info("Socket connected")


@socketio.on("join")
def join(data):
    username = data.get("username")
    if username:
        join_room(f"user:{username}")
        logger.info(f"{username} joined room")


# ------------ HEALTH ------------
@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ------------ RUN ------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=True)
