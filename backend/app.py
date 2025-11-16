import os
import json
import hmac
import hashlib
import secrets
import logging
import sys
import traceback

from datetime import datetime
from flask import Flask, request, jsonify, redirect, make_response, session
from flask_cors import CORS
from flask_socketio import SocketIO, join_room
from functools import wraps
from dotenv import load_dotenv

# Import requests normally (no monkey patching issues with gevent)
import requests

load_dotenv()

# ------------ APP CONFIG ------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_PATH'] = '/'

GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost')
APP_URL = os.getenv('APP_URL', 'http://localhost')   # Your NGROK domain
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', secrets.token_hex(32))

DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'user.json')
REVIEWS_FILE = os.path.join(DATA_DIR, 'review.json')

os.makedirs(DATA_DIR, exist_ok=True)
for f in [USERS_FILE, REVIEWS_FILE]:
    if not os.path.exists(f):
        with open(f, 'w') as file:
            json.dump({}, file)

# CORS Configuration - Allow credentials
ALLOWED_ORIGINS = [FRONTEND_URL, "http://localhost", "http://localhost:80", APP_URL]
CORS(app, 
     origins=ALLOWED_ORIGINS, 
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     expose_headers=["Set-Cookie"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# Use gevent-websocket instead of eventlet
socketio = SocketIO(app, 
                    cors_allowed_origins=ALLOWED_ORIGINS, 
                    async_mode='gevent',
                    cookie=True,
                    logger=True,
                    engineio_logger=True)

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
        logger.debug(f"Auth check - Token present: {bool(token)}")
        
        if not token:
            logger.warning("No token in cookies")
            return jsonify({'logged_in': False, 'error': 'No token'}), 401

        users = load_json(USERS_FILE)
        user = next((u for u in users.values() if u.get('token') == token), None)

        if not user:
            logger.warning(f"No user found for token")
            return jsonify({'logged_in': False, 'error': 'Invalid token'}), 401

        request.user = user
        logger.debug(f"Auth successful for user: {user['username']}")
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
    """Initiate GitHub OAuth flow"""
    state = secrets.token_hex(16)
    
    # Store state in Flask session (server-side)
    session['oauth_state'] = state
    session.modified = True
    
    logger.info(f"OAuth initiated with state: {state}")
    logger.info(f"Redirect URI: {APP_URL}/api/auth/github/callback")
    
    redirect_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&scope=repo%20read:user%20user:email"
        f"&redirect_uri={APP_URL}/api/auth/github/callback"
        f"&state={state}"
    )
    
    logger.debug(f"Redirecting to: {redirect_url}")
    return redirect(redirect_url)


@app.route("/api/auth/github/callback")
def github_callback():
    """Handle GitHub OAuth callback"""
    code = request.args.get("code")
    state = request.args.get("state")
    stored_state = session.get("oauth_state")
    
    logger.info(f"OAuth callback received")
    logger.debug(f"Code present: {bool(code)}")
    logger.debug(f"State from URL: {state}")
    logger.debug(f"State from session: {stored_state}")
    logger.debug(f"Session contents: {dict(session)}")

    # Validate code
    if not code:
        logger.error("No code received from GitHub")
        return redirect(f"{FRONTEND_URL}?error=no_code")

    # Validate state
    if not state or not stored_state:
        logger.error(f"State validation failed - URL state: {state}, Session state: {stored_state}")
        return redirect(f"{FRONTEND_URL}?error=missing_state")
    
    if stored_state != state:
        logger.error(f"State mismatch - Expected: {stored_state}, Got: {state}")
        return redirect(f"{FRONTEND_URL}?error=invalid_state")

    # Clear the state from session
    session.pop('oauth_state', None)

    # Exchange code for token
    try:
        logger.info("Exchanging code for access token")
        token_resp = requests.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": f"{APP_URL}/api/auth/github/callback"
            },
            timeout=10
        )
        
        token_data = token_resp.json()
        logger.debug(f"Token response status: {token_resp.status_code}")
        
        gh_token = token_data.get("access_token")
        if not gh_token:
            logger.error(f"No access token in response: {token_data}")
            return redirect(f"{FRONTEND_URL}?error=token_failed")

        # Fetch GitHub user info
        logger.info("Fetching GitHub user info")
        user_resp = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {gh_token}"},
            timeout=10
        )
        
        if user_resp.status_code != 200:
            logger.error(f"Failed to fetch user info: {user_resp.status_code}")
            return redirect(f"{FRONTEND_URL}?error=user_fetch_failed")
        
        user_data = user_resp.json()
        username = user_data.get("login")
        avatar = user_data.get("avatar_url")
        
        logger.info(f"Successfully authenticated user: {username}")

        # Save user in database
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
        resp.set_cookie(
            'gh_token', 
            gh_token, 
            httponly=True, 
            samesite='Lax',
            max_age=86400 * 30,  # 30 days
            path='/'
        )
        
        logger.info(f"Login successful for {username}, redirecting to dashboard")
        return resp
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error during OAuth: {str(e)}")
        return redirect(f"{FRONTEND_URL}?error=network_error")
    except Exception as e:
        logger.error(f"Unexpected error during OAuth: {str(e)}")
        logger.error(traceback.format_exc())
        return redirect(f"{FRONTEND_URL}?error=server_error")


# ------------ USER DATA ------------
@app.route("/api/me")
def get_user():
    """Get current user info"""
    token = request.cookies.get('gh_token')
    
    if not token:
        logger.debug("No token in /api/me request")
        return jsonify({"logged_in": False})

    users = load_json(USERS_FILE)
    user = next((u for u in users.values() if u.get("token") == token), None)

    if not user:
        logger.debug("Token invalid in /api/me request")
        return jsonify({"logged_in": False})

    logger.debug(f"User {user['username']} fetched their profile")
    return jsonify({
        "logged_in": True,
        "username": user["username"],
        "avatar": user["avatar"],
        "repos_count": len(user.get("repos", []))
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    """Logout user"""
    resp = make_response(jsonify({"success": True}))
    resp.set_cookie('gh_token', '', expires=0, path='/')
    return resp


# ------------ REPOS ------------
@app.route("/api/repos")
@require_auth
def get_repos():
    """Fetch user's GitHub repositories"""
    try:
        resp = requests.get(
            "https://api.github.com/user/repos",
            headers={"Authorization": f"Bearer {request.user['token']}"},
            params={"per_page": 100, "sort": "updated"},
            timeout=10
        )
        
        if resp.status_code != 200:
            logger.error(f"GitHub API error: {resp.status_code}")
            return jsonify({"error": "Failed to fetch repos"}), 500

        repos = resp.json()
        formatted = [
            {
                "id": r["id"],
                "name": r["name"],
                "full_name": r["full_name"],
                "language": r.get("language"),
                "private": r.get("private", False)
            }
            for r in repos
        ]

        # Save to user
        users = load_json(USERS_FILE)
        if request.user["username"] in users:
            users[request.user["username"]]["repos"] = formatted
            save_json(USERS_FILE, users)

        logger.info(f"Fetched {len(formatted)} repos for {request.user['username']}")
        return jsonify(formatted)
        
    except Exception as e:
        logger.error(f"Error fetching repos: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Server error"}), 500


# ------------ REVIEWS ------------
@app.route("/api/reviews")
@require_auth
def get_reviews():
    """Get all code reviews"""
    reviews = load_json(REVIEWS_FILE)
    return jsonify(list(reviews.values()))


# ------------ ANALYTICS ------------
@app.route("/api/analytics")
@require_auth
def get_analytics():
    """Get analytics data"""
    reviews = load_json(REVIEWS_FILE)
    analytics = {
        "total_reviews": len(reviews),
        "issues_by_severity": {},
        "issues_by_type": {},
        "reviews_per_repo": {}
    }

    for r in reviews.values():
        for issue in r.get("issues", []):
            severity = issue.get("severity", "unknown")
            issue_type = issue.get("type", "unknown")
            
            analytics["issues_by_severity"][severity] = \
                analytics["issues_by_severity"].get(severity, 0) + 1

            analytics["issues_by_type"][issue_type] = \
                analytics["issues_by_type"].get(issue_type, 0) + 1

        repo = r.get("repo", "unknown")
        analytics["reviews_per_repo"][repo] = \
            analytics["reviews_per_repo"].get(repo, 0) + 1

    return jsonify(analytics)


# ------------ WEBHOOK ------------
@app.route("/webhook", methods=["POST"])
def webhook():
    """Handle GitHub webhook for pull requests"""
    signature = request.headers.get("X-Hub-Signature-256")

    if not verify_webhook_signature(request.get_data(), signature):
        logger.warning("Invalid webhook signature")
        return jsonify({"error": "Invalid signature"}), 401

    payload = request.get_json()
    action = payload.get("action")
    
    logger.info(f"Webhook received: {action}")

    if action not in ["opened", "synchronize", "reopened"]:
        return jsonify({"message": "Ignored action"}), 200

    pr = payload.get("pull_request", {})
    repo_name = payload.get("repository", {}).get("full_name")

    # Create a review entry
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

    logger.info(f"Processed webhook for PR #{pr.get('number')} in {repo_name}")
    return jsonify({"message": "Webhook processed"}), 200


# ------------ SOCKET.IO ------------
@socketio.on("connect")
def connected():
    logger.info(f"Socket connected: {request.sid}")


@socketio.on("disconnect")
def disconnected():
    logger.info(f"Socket disconnected: {request.sid}")


@socketio.on("join")
def join(data):
    username = data.get("username")
    if username:
        join_room(f"user:{username}")
        logger.info(f"{username} joined their room")


# ------------ HEALTH ------------
@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat()
    })


@app.route("/")
def root():
    return jsonify({
        "service": "LinguaLint API",
        "status": "running"
    })


# ------------ RUN ------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    logger.info(f"Starting LinguaLint Backend on port {port}")
    logger.info(f"APP_URL: {APP_URL}")
    logger.info(f"FRONTEND_URL: {FRONTEND_URL}")
    socketio.run(app, host="0.0.0.0", port=port, debug=True)