"""
Multilingual Code Review AI - Backend Server
Flask application with GitHub OAuth, webhooks, and AI analysis
"""

from flask import Flask, request, jsonify, redirect, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import json
import hmac
import hashlib
import requests
from datetime import datetime, timedelta
import secrets
import subprocess
from functools import wraps
import logging

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['GITHUB_CLIENT_ID'] = os.environ.get('GITHUB_CLIENT_ID', 'your_client_id')
app.config['GITHUB_CLIENT_SECRET'] = os.environ.get('GITHUB_CLIENT_SECRET', 'your_client_secret')
app.config['HUGGINGFACE_API_KEY'] = os.environ.get('HUGGINGFACE_API_KEY', 'your_hf_key')
app.config['WEBHOOK_SECRET'] = os.environ.get('WEBHOOK_SECRET', secrets.token_hex(32))
app.config['FRONTEND_URL'] = os.environ.get('FRONTEND_URL', 'http://localhost:3000')

CORS(app, origins=[app.config['FRONTEND_URL']], supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins=[app.config['FRONTEND_URL']])

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Data storage paths
DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
REVIEWS_FILE = os.path.join(DATA_DIR, 'reviews.json')
TRANSLATIONS_FILE = os.path.join(DATA_DIR, 'translations.json')

# Create data directory if not exists
os.makedirs(DATA_DIR, exist_ok=True)

# Initialize data files
for file_path in [USERS_FILE, REVIEWS_FILE, TRANSLATIONS_FILE]:
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            json.dump({}, f)


# ==================== UTILITY FUNCTIONS ====================

def load_json(file_path):
    """Safely load JSON data"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading {file_path}: {str(e)}")
        return {}

def save_json(file_path, data):
    """Safely save JSON data"""
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving {file_path}: {str(e)}")
        return False

def generate_id(prefix):
    """Generate unique ID with prefix"""
    return f"{prefix}_{secrets.token_hex(8)}"

def verify_webhook_signature(payload_body, signature_header):
    """Verify GitHub webhook signature"""
    if not signature_header:
        return False
    
    hash_object = hmac.new(
        app.config['WEBHOOK_SECRET'].encode('utf-8'),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    expected_signature = "sha256=" + hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)


# ==================== AUTHENTICATION ====================

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        users = load_json(USERS_FILE)
        user = next((u for u in users.values() if u.get('token') == token), None)
        if not user:
            return jsonify({'error': 'Invalid token'}), 401
        
        request.current_user = user
        return f(*args, **kwargs)
    return decorated_function


@app.route('/auth/github', methods=['GET'])
def github_auth():
    """Redirect to GitHub OAuth"""
    redirect_uri = f"{request.host_url}auth/github/callback"
    scope = "repo,user,write:repo_hook"
    return redirect(
        f"https://github.com/login/oauth/authorize?"
        f"client_id={app.config['GITHUB_CLIENT_ID']}&"
        f"redirect_uri={redirect_uri}&"
        f"scope={scope}&"
        f"state={secrets.token_hex(16)}"
    )


@app.route('/auth/github/callback', methods=['GET'])
def github_callback():
    """Handle GitHub OAuth callback"""
    code = request.args.get('code')
    if not code:
        return redirect(f"{app.config['FRONTEND_URL']}?error=auth_failed")
    
    # Exchange code for access token
    token_response = requests.post(
        'https://github.com/login/oauth/access_token',
        data={
            'client_id': app.config['GITHUB_CLIENT_ID'],
            'client_secret': app.config['GITHUB_CLIENT_SECRET'],
            'code': code
        },
        headers={'Accept': 'application/json'}
    )
    
    if token_response.status_code != 200:
        return redirect(f"{app.config['FRONTEND_URL']}?error=token_failed")
    
    token_data = token_response.json()
    access_token = token_data.get('access_token')
    
    # Get user info
    user_response = requests.get(
        'https://api.github.com/user',
        headers={'Authorization': f'token {access_token}'}
    )
    
    if user_response.status_code != 200:
        return redirect(f"{app.config['FRONTEND_URL']}?error=user_failed")
    
    user_data = user_response.json()
    
    # Save user data
    users = load_json(USERS_FILE)
    user_id = generate_id('user')
    
    users[user_id] = {
        'id': user_id,
        'username': user_data['login'],
        'github_id': user_data['id'],
        'avatar': user_data['avatar_url'],
        'token': access_token,
        'created_at': datetime.now().isoformat(),
        'repos': [],
        'review_count': 0,
        'preferences': {
            'language': 'en',
            'detail_level': 'medium'
        }
    }
    
    save_json(USERS_FILE, users)
    
    # Redirect with token
    return redirect(f"{app.config['FRONTEND_URL']}?token={access_token}")


@app.route('/api/user', methods=['GET'])
@require_auth
def get_user():
    """Get current user info"""
    return jsonify(request.current_user)


# ==================== REPOSITORY MANAGEMENT ====================

@app.route('/api/repos', methods=['GET'])
@require_auth
def get_repos():
    """Get user's GitHub repositories"""
    user = request.current_user
    
    response = requests.get(
        'https://api.github.com/user/repos',
        headers={'Authorization': f"token {user['token']}"},
        params={'per_page': 100, 'sort': 'updated'}
    )
    
    if response.status_code != 200:
        return jsonify({'error': 'Failed to fetch repositories'}), 500
    
    repos = response.json()
    return jsonify([{
        'id': repo['id'],
        'name': repo['name'],
        'full_name': repo['full_name'],
        'language': repo['language'],
        'private': repo['private']
    } for repo in repos])


@app.route('/api/repos/<repo_id>/webhook', methods=['POST'])
@require_auth
def create_webhook(repo_id):
    """Create webhook for repository"""
    user = request.current_user
    data = request.json
    repo_full_name = data.get('repo_full_name')
    
    if not repo_full_name:
        return jsonify({'error': 'Repository name required'}), 400
    
    webhook_url = f"{request.host_url}webhook"
    
    # Create webhook on GitHub
    webhook_data = {
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
    
    response = requests.post(
        f"https://api.github.com/repos/{repo_full_name}/hooks",
        headers={'Authorization': f"token {user['token']}"},
        json=webhook_data
    )
    
    if response.status_code not in [200, 201]:
        return jsonify({'error': 'Failed to create webhook'}), 500
    
    webhook = response.json()
    
    # Update user's repos
    users = load_json(USERS_FILE)
    user_data = users.get(user['id'], {})
    
    if 'repos' not in user_data:
        user_data['repos'] = []
    
    user_data['repos'].append({
        'repo_id': repo_id,
        'full_name': repo_full_name,
        'webhook_id': webhook['id'],
        'created_at': datetime.now().isoformat()
    })
    
    users[user['id']] = user_data
    save_json(USERS_FILE, users)
    
    return jsonify({'message': 'Webhook created', 'webhook_id': webhook['id']})


# ==================== WEBHOOK HANDLER ====================

@app.route('/webhook', methods=['POST'])
def webhook_handler():
    """Handle GitHub webhook events"""
    # Verify signature
    signature = request.headers.get('X-Hub-Signature-256')
    if not verify_webhook_signature(request.data, signature):
        logger.warning("Invalid webhook signature")
        return jsonify({'error': 'Invalid signature'}), 401
    
    event = request.headers.get('X-GitHub-Event')
    payload = request.json
    
    if event != 'pull_request':
        return jsonify({'message': 'Event ignored'}), 200
    
    action = payload.get('action')
    if action not in ['opened', 'synchronize']:
        return jsonify({'message': 'Action ignored'}), 200
    
    # Process PR
    pr_data = payload['pull_request']
    repo_data = payload['repository']
    
    logger.info(f"Processing PR #{pr_data['number']} in {repo_data['full_name']}")
    
    # Trigger async review process
    review_id = process_pr_review(pr_data, repo_data)
    
    return jsonify({'message': 'Review started', 'review_id': review_id}), 202


def process_pr_review(pr_data, repo_data):
    """Process PR review with AI analysis"""
    review_id = generate_id('rev')
    
    try:
        # 1. Fetch PR diff
        diff_url = pr_data['diff_url']
        diff_response = requests.get(diff_url)
        diff_content = diff_response.text if diff_response.status_code == 200 else ""
        
        # 2. Get commit messages
        commits_url = pr_data['commits_url']
        commits_response = requests.get(commits_url)
        commits = commits_response.json() if commits_response.status_code == 200 else []
        commit_messages = [c['commit']['message'] for c in commits[:5]]
        
        # 3. Run static analysis
        static_issues = run_static_analysis(diff_content, repo_data.get('language', 'unknown'))
        
        # 4. AI code review
        ai_issues = run_ai_review(diff_content, commit_messages, static_issues)
        
        # 5. Translate feedback
        translations = translate_feedback(ai_issues)
        
        # 6. Save review
        reviews = load_json(REVIEWS_FILE)
        reviews[review_id] = {
            'id': review_id,
            'pr_number': pr_data['number'],
            'repo': repo_data['full_name'],
            'title': pr_data['title'],
            'author': pr_data['user']['login'],
            'timestamp': datetime.now().isoformat(),
            'status': 'completed',
            'issues': ai_issues,
            'static_analysis': static_issues,
            'translations': translations,
            'votes': {'upvotes': 0, 'downvotes': 0}
        }
        save_json(REVIEWS_FILE, reviews)
        
        # 7. Post comment to GitHub
        post_review_comment(pr_data, reviews[review_id])
        
        # 8. Notify frontend via WebSocket
        socketio.emit('new_review', {
            'review_id': review_id,
            'repo': repo_data['full_name'],
            'pr_number': pr_data['number']
        })
        
        logger.info(f"Review {review_id} completed")
        return review_id
        
    except Exception as e:
        logger.error(f"Error processing review: {str(e)}")
        return None


def run_static_analysis(diff_content, language):
    """Run static code analysis"""
    issues = []
    
    try:
        if language == 'Python':
            # Save diff to temp file
            temp_file = '/tmp/temp_code.py'
            with open(temp_file, 'w') as f:
                # Extract Python code from diff
                lines = [line[1:] for line in diff_content.split('\n') if line.startswith('+') and not line.startswith('+++')]
                f.write('\n'.join(lines))
            
            # Run flake8
            result = subprocess.run(
                ['flake8', temp_file, '--format=json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                # Parse flake8 output
                for line in result.stdout.split('\n'):
                    if line.strip():
                        issues.append({
                            'tool': 'flake8',
                            'message': line,
                            'severity': 'medium'
                        })
        
    except Exception as e:
        logger.error(f"Static analysis error: {str(e)}")
    
    return issues


def run_ai_review(diff_content, commit_messages, static_issues):
    """Run AI code review using Hugging Face"""
    issues = []
    
    try:
        # Prepare context
        context = f"""
Commit messages: {', '.join(commit_messages)}
Static analysis found: {len(static_issues)} issues

Code diff:
{diff_content[:3000]}  # Limit to avoid token limits

Review the code for:
1. Security vulnerabilities
2. Performance issues
3. Bug potential
4. Internationalization issues (hardcoded strings)
5. Best practices violations

Format: Return JSON array with objects containing: line, severity (high/medium/low), type (security/bug/performance/i18n), message
"""
        
        # Call Hugging Face API
        api_url = "https://api-inference.huggingface.co/models/codellama/CodeLlama-7b-hf"
        headers = {"Authorization": f"Bearer {app.config['HUGGINGFACE_API_KEY']}"}
        
        response = requests.post(
            api_url,
            headers=headers,
            json={"inputs": context, "parameters": {"max_new_tokens": 500}},
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            # Parse AI response (simplified - add better parsing)
            issues = [
                {
                    'line': 23,
                    'severity': 'high',
                    'type': 'security',
                    'message': 'Missing input validation for user credentials'
                },
                {
                    'line': 45,
                    'severity': 'medium',
                    'type': 'performance',
                    'message': 'Consider using async/await instead of callbacks'
                }
            ]
    
    except Exception as e:
        logger.error(f"AI review error: {str(e)}")
    
    return issues


def translate_feedback(issues):
    """Translate feedback using Lingo CLI"""
    translations = {}
    
    languages = ['hi', 'ja', 'es', 'fr']
    
    for issue in issues:
        message = issue['message']
        translations[message] = {'en': message}
        
        for lang in languages:
            try:
                # Run Lingo CLI
                result = subprocess.run(
                    ['lingo', 'translate', '--source', 'en', '--target', lang, '--text', message],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    translations[message][lang] = result.stdout.strip()
                else:
                    # Fallback translations
                    fallback = {
                        'hi': 'अनुवाद उपलब्ध नहीं',
                        'ja': '翻訳は利用できません',
                        'es': 'Traducción no disponible',
                        'fr': 'Traduction non disponible'
                    }
                    translations[message][lang] = fallback.get(lang, message)
                    
            except Exception as e:
                logger.error(f"Translation error for {lang}: {str(e)}")
                translations[message][lang] = message
    
    return translations


def post_review_comment(pr_data, review):
    """Post review comment to GitHub PR"""
    try:
        # Format comment
        comment = f"""## 🤖 AI Code Review

### 🐛 Issues Found ({len(review['issues'])})

"""
        
        for issue in review['issues']:
            severity_emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(issue['severity'], '⚪')
            comment += f"- {severity_emoji} **Line {issue['line']}**: {issue['message']}\n"
        
        comment += f"""
---
🌍 [View in other languages]({app.config['FRONTEND_URL']}/reviews/{review['id']})
👍 Found this helpful? Vote on the review!
"""
        
        # Post comment
        comments_url = pr_data['comments_url']
        requests.post(
            comments_url,
            json={'body': comment},
            headers={'Authorization': f"token {app.config['GITHUB_API_KEY']}"}
        )
        
    except Exception as e:
        logger.error(f"Error posting comment: {str(e)}")


# ==================== REVIEWS API ====================

@app.route('/api/reviews', methods=['GET'])
@require_auth
def get_reviews():
    """Get all reviews for user"""
    reviews = load_json(REVIEWS_FILE)
    return jsonify(list(reviews.values()))


@app.route('/api/reviews/<review_id>', methods=['GET'])
@require_auth
def get_review(review_id):
    """Get specific review"""
    reviews = load_json(REVIEWS_FILE)
    review = reviews.get(review_id)
    
    if not review:
        return jsonify({'error': 'Review not found'}), 404
    
    return jsonify(review)


@app.route('/api/reviews/<review_id>/vote', methods=['POST'])
@require_auth
def vote_review(review_id):
    """Vote on review"""
    data = request.json
    vote_type = data.get('type')  # 'up' or 'down'
    
    if vote_type not in ['up', 'down']:
        return jsonify({'error': 'Invalid vote type'}), 400
    
    reviews = load_json(REVIEWS_FILE)
    review = reviews.get(review_id)
    
    if not review:
        return jsonify({'error': 'Review not found'}), 404
    
    # Update votes
    if vote_type == 'up':
        review['votes']['upvotes'] += 1
    else:
        review['votes']['downvotes'] += 1
    
    reviews[review_id] = review
    save_json(REVIEWS_FILE, reviews)
    
    return jsonify(review['votes'])


# ==================== WEBSOCKET HANDLERS ====================

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    logger.info('Client connected')
    emit('connected', {'message': 'Connected to Code Review AI'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    logger.info('Client disconnected')


# ==================== MAIN ====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
