# app.py
import os
import json
import hmac
import hashlib
import threading
import requests
import secrets
import subprocess
import logging
from datetime import datetime
from flask import Flask, request, jsonify, redirect, make_response
from flask_cors import CORS
from flask_socketio import SocketIO
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

# ---------- CONFIG ----------
app = Flask(__name__, static_folder=None)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['GITHUB_CLIENT_ID'] = os.getenv('GITHUB_CLIENT_ID')
app.config['GITHUB_CLIENT_SECRET'] = os.getenv('GITHUB_CLIENT_SECRET')
# app.config['GITHUB_BOT_TOKEN'] = os.getenv('GITHUB_BOT_TOKEN')  # optional bot token to post comments
app.config['HUGGINGFACE_API_KEY'] = os.getenv('HUGGINGFACE_API_KEY')
app.config['WEBHOOK_SECRET'] = os.getenv('WEBHOOK_SECRET', secrets.token_hex(32))
app.config['FRONTEND_URL'] = os.getenv('FRONTEND_URL', 'http://localhost:5173')
app.config['APP_URL'] = os.getenv('APP_URL')

# Data files (kept under backend/data for your project structure)
DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'user.json')
REVIEWS_FILE = os.path.join(DATA_DIR, 'review.json')

os.makedirs(DATA_DIR, exist_ok=True)
for p in [USERS_FILE, REVIEWS_FILE]:
    if not os.path.exists(p):
        with open(p, 'w') as f:
            json.dump({}, f)

# Setup CORS & SocketIO
CORS(app, origins=[app.config['FRONTEND_URL']], supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins=[app.config['FRONTEND_URL']])

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("LinguaLintBackend")


# ---------- UTILITIES ----------
def load_json(path):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error("load_json error %s %s", path, e)
        return {}


def save_json(path, data):
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error("save_json error %s %s", path, e)
        return False


def generate_id(prefix):
    return f"{prefix}_{secrets.token_hex(8)}"


def verify_webhook_signature(payload_body, signature_header):
    if not signature_header:
        return False
    mac = hmac.new(app.config['WEBHOOK_SECRET'].encode('utf-8'),
                   msg=payload_body,
                   digestmod=hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()
    return hmac.compare_digest(expected, signature_header)


# ---------- AUTH HELPERS & DECORATOR ----------
def get_token_from_cookie():
    return request.cookies.get('gh_token')


def require_auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = get_token_from_cookie()
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        users = load_json(USERS_FILE)
        user = next((u for u in users.values() if u.get('token') == token), None)
        if not user:
            return jsonify({'error': 'Invalid token'}), 401
        request.current_user = user
        return func(*args, **kwargs)
    return wrapper


# ---------- AUTH ROUTES ----------
@app.route('/auth/github', methods=['GET'])
def github_auth():
    # Generate state and set as cookie to validate later (simple CSRF protection)
    state = secrets.token_hex(16)
    auth_url = (
        "https://github.com/login/oauth/authorize"
        f"?client_id={app.config['GITHUB_CLIENT_ID']}"
        f"&redirect_uri={app.config['APP_URL']}/auth/github/callback"
        "&scope=repo,user,write:repo_hook"
        f"&state={state}"
    )
    resp = make_response(redirect(auth_url))
    resp.set_cookie('oauth_state', state, httponly=True, samesite='Lax')
    return resp


@app.route('/auth/github/callback', methods=['GET'])
def github_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    saved_state = request.cookies.get('oauth_state')

    if not code or not state or (saved_state and state != saved_state):
        logger.warning("OAuth callback missing code or invalid state")
        return redirect(f"{app.config['FRONTEND_URL']}?error=auth_failed")

    # Exchange code for access token
    token_resp = requests.post(
        'https://github.com/login/oauth/access_token',
        headers={'Accept': 'application/json'},
        data={
            'client_id': app.config['GITHUB_CLIENT_ID'],
            'client_secret': app.config['GITHUB_CLIENT_SECRET'],
            'code': code
        },
        timeout=10
    )
    if token_resp.status_code != 200:
        logger.error("Token exchange failed: %s", token_resp.text)
        return redirect(f"{app.config['FRONTEND_URL']}?error=token_failed")
    token_data = token_resp.json()
    access_token = token_data.get('access_token')
    if not access_token:
        logger.error("No access token returned")
        return redirect(f"{app.config['FRONTEND_URL']}?error=no_token")

    # Get user profile
    user_resp = requests.get('https://api.github.com/user',
                             headers={'Authorization': f'token {access_token}'},
                             timeout=10)
    if user_resp.status_code != 200:
        logger.error("User fetch failed: %s", user_resp.text)
        return redirect(f"{app.config['FRONTEND_URL']}?error=user_failed")

    user_data = user_resp.json()
    github_id = user_data['id']
    username = user_data.get('login')

    # Save / update user (dedupe by github_id)
    users = load_json(USERS_FILE)
    existing_item_key = next((k for k, v in users.items() if v.get('github_id') == github_id), None)

    if existing_item_key:
        users[existing_item_key]['token'] = access_token
        users[existing_item_key]['username'] = username
        users[existing_item_key]['avatar'] = user_data.get('avatar_url')
        users[existing_item_key]['updated_at'] = datetime.now().isoformat()
        user_record = users[existing_item_key]
        logger.info("Updated existing user %s", username)
    else:
        user_id = generate_id('user')
        user_record = {
            'id': user_id,
            'github_id': github_id,
            'username': username,
            'avatar': user_data.get('avatar_url'),
            'token': access_token,
            'created_at': datetime.now().isoformat(),
            'repos': []
        }
        users[user_id] = user_record
        logger.info("Created new user %s", username)

    save_json(USERS_FILE, users)

    # Return token in a secure HttpOnly cookie (never in URL)
    resp = make_response(redirect(app.config['FRONTEND_URL']))
    resp.set_cookie('gh_token',
                    access_token,
                    httponly=True,
                    secure=False,   # set to True in production (HTTPS)
                    samesite='Lax',
                    max_age=24 * 3600)
    # clear state cookie
    resp.set_cookie('oauth_state', '', expires=0)
    return resp


@app.route('/api/me', methods=['GET'])
def api_me():
    token = get_token_from_cookie()
    if not token:
        return jsonify({'logged_in': False}), 200
    users = load_json(USERS_FILE)
    user = next((u for u in users.values() if u.get('token') == token), None)
    if not user:
        return jsonify({'logged_in': False}), 200
    return jsonify({'logged_in': True, 'username': user.get('username'), 'avatar': user.get('avatar')}), 200


@app.route('/api/logout', methods=['POST'])
def api_logout():
    resp = make_response(jsonify({'message': 'logged out'}))
    resp.set_cookie('gh_token', '', expires=0)
    return resp


# ---------- REPO & WEBHOOK ENDPOINTS ----------
@app.route('/api/repos', methods=['GET'])
@require_auth
def api_get_repos():
    user = request.current_user
    token = user['token']
    resp = requests.get('https://api.github.com/user/repos',
                        headers={'Authorization': f'token {token}'},
                        params={'per_page': 100, 'sort': 'updated'},
                        timeout=10)
    if resp.status_code != 200:
        logger.error("Failed to fetch repos: %s", resp.text)
        return jsonify({'error': 'Failed to fetch repositories'}), 500
    repos = resp.json()
    simplified = [{
        'id': r['id'],
        'name': r['name'],
        'full_name': r['full_name'],
        'language': r.get('language'),
        'private': r.get('private', False)
    } for r in repos]
    return jsonify(simplified), 200


@app.route('/api/repos/webhook', methods=['POST'])
@require_auth
def api_create_webhook():
    """
    Body: { "repo_full_name": "owner/repo" }
    """
    user = request.current_user
    data = request.get_json() or {}
    repo_full_name = data.get('repo_full_name')
    if not repo_full_name:
        return jsonify({'error': 'repo_full_name required'}), 400

    webhook_url = f"{app.config['APP_URL']}/webhook"
    payload = {
        'name': 'web',
        'active': True,
        'events': ['pull_request'],
        'config': {
            'url': webhook_url,
            'content_type': 'json',
            'secret': app.config['WEBHOOK_SECRET'],
            'insecure_ssl': '0'
        }
    }

    r = requests.post(f"https://api.github.com/repos/{repo_full_name}/hooks",
                      headers={'Authorization': f'token {user["token"]}'},
                      json=payload, timeout=10)

    if r.status_code not in (200, 201):
        logger.error("Webhook creation failed: %s", r.text)
        return jsonify({'error': 'Failed to create webhook', 'details': r.text}), 500

    webhook = r.json()
    # store webhook info in user's data
    users = load_json(USERS_FILE)
    # find user key
    ukey = next((k for k, v in users.items() if v.get('github_id') == user.get('github_id')), None)
    if ukey:
        u = users[ukey]
        u.setdefault('repos', []).append({
            'full_name': repo_full_name,
            'webhook_id': webhook.get('id'),
            'created_at': datetime.now().isoformat()
        })
        save_json(USERS_FILE, users)

    return jsonify({'message': 'webhook created', 'webhook_id': webhook.get('id')}), 201


# ---------- WEBHOOK RECEIVER ----------
@app.route('/webhook', methods=['POST'])
def webhook_receiver():
    signature = request.headers.get('X-Hub-Signature-256')
    if not verify_webhook_signature(request.data, signature):
        logger.warning("Invalid webhook signature")
        return jsonify({'error': 'Invalid signature'}), 401

    event = request.headers.get('X-GitHub-Event')
    payload = request.json or {}

    if event != 'pull_request':
        return jsonify({'message': 'ignored'}), 200

    action = payload.get('action')
    if action not in ('opened', 'synchronize'):
        return jsonify({'message': 'ignored'}), 200

    pr = payload.get('pull_request')
    repo = payload.get('repository')

    logger.info("Webhook PR event: %s #%s", repo.get('full_name'), pr.get('number'))

    # Process in background thread so webhook returns quickly
    t = threading.Thread(target=process_pr_review, args=(pr, repo), daemon=True)
    t.start()

    return jsonify({'message': 'review started'}), 202


# ---------- PR PROCESSING ----------
def process_pr_review(pr_data, repo_data):
    """
    1) fetch diff & commits
    2) static analysis
    3) AI review
    4) translations
    5) save review & comment on PR
    """
    try:
        review_id = generate_id('rev')
        owner_repo = repo_data.get('full_name')

        # Prefer authenticated calls (some repos private)
        auth_token = app.config.get('GITHUB_BOT_TOKEN') or None

        headers = {'Accept': 'application/vnd.github.v3+json'}
        if auth_token:
            headers['Authorization'] = f'token {auth_token}'

        # 1. diff (use diff_url)
        diff_url = pr_data.get('diff_url')
        diff_resp = requests.get(diff_url, headers=headers, timeout=10)
        diff_content = diff_resp.text if diff_resp.status_code == 200 else ""

        # 2. commits
        commits_url = pr_data.get('commits_url')
        commits_resp = requests.get(commits_url, headers=headers, timeout=10)
        commits_list = commits_resp.json() if commits_resp.status_code == 200 else []
        commit_messages = [c.get('commit', {}).get('message', '') for c in commits_list][:10]

        # 3. static analysis
        language = repo_data.get('language') or 'unknown'
        static_issues = run_static_analysis(diff_content, language)

        # 4. ai review
        ai_issues = run_ai_review(diff_content, commit_messages, static_issues)

        # 5. translations
        translations = translate_feedback(ai_issues)

        # 6. save review
        reviews = load_json(REVIEWS_FILE)
        reviews[review_id] = {
            'id': review_id,
            'pr_number': pr_data.get('number'),
            'repo': owner_repo,
            'title': pr_data.get('title'),
            'author': pr_data.get('user', {}).get('login'),
            'timestamp': datetime.now().isoformat(),
            'status': 'completed',
            'issues': ai_issues,
            'static_analysis': static_issues,
            'translations': translations,
            'votes': {'upvotes': 0, 'downvotes': 0}
        }
        save_json(REVIEWS_FILE, reviews)

        # 7. Post review comment to GitHub
        post_review_comment(pr_data, reviews[review_id])

        # 8. Notify frontend via socket
        try:
            socketio.emit('new_review', {'review_id': review_id, 'repo': owner_repo, 'pr_number': pr_data.get('number')})
        except Exception as e:
            logger.warning("Socket emit failed: %s", e)

        logger.info("Completed review %s for PR %s", review_id, pr_data.get('number'))
        return review_id

    except Exception as e:
        logger.exception("process_pr_review error: %s", e)
        return None


# ---------- STATIC ANALYSIS ----------
def run_static_analysis(diff_content, language):
    issues = []
    try:
        if language and 'Python' in language:
            temp = '/tmp/lingualint_temp.py'
            lines = [ln[1:] for ln in diff_content.splitlines() if ln.startswith('+') and not ln.startswith('+++')]
            with open(temp, 'w') as f:
                f.write('\n'.join(lines))
            # try flake8 if available
            try:
                proc = subprocess.run(['flake8', temp, '--format=default'], capture_output=True, text=True, timeout=8)
                out = proc.stdout.strip()
                if out:
                    for ln in out.splitlines():
                        issues.append({'tool': 'flake8', 'message': ln, 'severity': 'medium'})
            except FileNotFoundError:
                logger.info("flake8 not installed; skipping static analysis")
    except Exception as e:
        logger.exception("run_static_analysis error: %s", e)
    return issues


# ---------- AI REVIEW ----------
def run_ai_review(diff_content, commit_messages, static_issues):
    issues = []
    try:
        # Build prompt/context — keep it small
        context = {
            "commit_messages": commit_messages,
            "static_issues_count": len(static_issues),
            "diff_snippet": diff_content[:4000]
        }

        # Basic call to Hugging Face Inference (replace model as required)
        if app.config.get('HUGGINGFACE_API_KEY'):
            api_url = "https://api-inference.huggingface.co/models/facebook/incoder-1B"  # placeholder; change as needed
            headers = {"Authorization": f"Bearer {app.config['HUGGINGFACE_API_KEY']}"}
            payload = {"inputs": f"Review code: {context}", "parameters": {"max_new_tokens": 200}}
            resp = requests.post(api_url, headers=headers, json=payload, timeout=20)
            if resp.status_code == 200:
                # This is a naive parse; replace with real parser for your model
                text = resp.text
                # fallback: add dummy issues for demo
                issues = [
                    {'line': 10, 'severity': 'high', 'type': 'security', 'message': 'Potential SQL injection risk (example)'},
                    {'line': 42, 'severity': 'medium', 'type': 'performance', 'message': 'Consider caching results'}
                ]
            else:
                logger.warning("HF model call failed: %s", resp.text)
                # fallback
                issues = []
        else:
            # No HF key: return a simple heuristic issue for demo
            issues = [
                {'line': 1, 'severity': 'low', 'type': 'style', 'message': 'No AI key configured; this is a demo issue.'}
            ]
    except Exception as e:
        logger.exception("run_ai_review error: %s", e)
    return issues


# ---------- TRANSLATION (simple fallback) ----------
def translate_feedback(issues):
    # Simple offline fallback translations for demo (replace with real service)
    translations = {}
    mapping = {
        'hi': 'अनुवाद उपलब्ध नहीं',
        'ja': '翻訳は利用できません',
        'es': 'Traducción no disponible',
        'fr': 'Traduction non disponible'
    }
    for issue in issues:
        msg = issue.get('message')
        translations[msg] = {'en': msg}
        for lang, fallback in mapping.items():
            translations[msg][lang] = fallback
    return translations


# ---------- POST REVIEW COMMENT ----------
def post_review_comment(pr_data, review):
    try:
        body = f"## 🤖 LinguaLint - Automated Review\n\n**PR:** #{pr_data.get('number')}  \n**Issues found:** {len(review.get('issues', []))}\n\n"
        for iss in review.get('issues', []):
            body += f"- **{iss.get('severity').upper()}** (line {iss.get('line')}): {iss.get('message')}\n"

        body += f"\n---\nView the review dashboard: {app.config['FRONTEND_URL']}/reviews/{review.get('id')}\n"

        comments_url = pr_data.get('comments_url')
        headers = {'Accept': 'application/json'}
        token = app.config.get('GITHUB_BOT_TOKEN') or None

        if token:
            headers['Authorization'] = f'token {token}'
        else:
            # If no bot token, attempt to post using the PR author's token is not possible here.
            logger.info("No GITHUB_BOT_TOKEN set; skipping posting comment to GitHub")
            return

        r = requests.post(comments_url, headers=headers, json={'body': body}, timeout=10)
        if r.status_code not in (200, 201):
            logger.warning("Failed to post comment: %s", r.text)
    except Exception as e:
        logger.exception("post_review_comment error: %s", e)


# ---------- REVIEWS API ----------
@app.route('/api/reviews', methods=['GET'])
@require_auth
def api_get_reviews():
    reviews = load_json(REVIEWS_FILE)
    # return list
    return jsonify(list(reviews.values())), 200


@app.route('/api/reviews/<review_id>', methods=['GET'])
@require_auth
def api_get_review(review_id):
    reviews = load_json(REVIEWS_FILE)
    review = reviews.get(review_id)
    if not review:
        return jsonify({'error': 'not found'}), 404
    return jsonify(review), 200


# ---------- SOCKET HANDLERS ----------
@socketio.on('connect')
def on_connect():
    logger.info("Socket connected")


@socketio.on('disconnect')
def on_disconnect():
    logger.info("Socket disconnected")


# ---------- MAIN ----------
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
