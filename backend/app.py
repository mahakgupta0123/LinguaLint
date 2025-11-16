import os
import json
import hmac
import hashlib
import secrets
import logging
import sys
import traceback
import subprocess
import tempfile
import time
from datetime import datetime
from flask import Flask, request, jsonify, redirect, make_response
from flask_cors import CORS
from flask_socketio import SocketIO, join_room
from functools import wraps
from dotenv import load_dotenv
import requests
import re

load_dotenv()

# ------------ APP CONFIG ------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = '/tmp/flask_session'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_PERMANENT_LIFETIME'] = 3600

GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost')
APP_URL = os.getenv('APP_URL', 'http://localhost')
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', secrets.token_hex(32))
HUGGINGFACE_API_KEY = os.getenv('HUGGINGFACE_API_KEY')
LINGODOTDEV_API_KEY = os.getenv('LINGODOTDEV_API_KEY')

DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'user.json')
REVIEWS_FILE = os.path.join(DATA_DIR, 'review.json')
OAUTH_STATES_FILE = os.path.join(DATA_DIR, 'oauth_states.json')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs('/tmp/flask_session', exist_ok=True)
for f in [USERS_FILE, REVIEWS_FILE, OAUTH_STATES_FILE]:
    if not os.path.exists(f):
        with open(f, 'w') as file:
            json.dump({}, file)

ALLOWED_ORIGINS = [FRONTEND_URL, "http://localhost", "http://localhost:80", APP_URL]
CORS(app,
     origins=ALLOWED_ORIGINS,
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     expose_headers=["Set-Cookie"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

socketio = SocketIO(app,
                    cors_allowed_origins=ALLOWED_ORIGINS,
                    async_mode='threading',
                    cookie=True,
                    logger=True,
                    engineio_logger=True)

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("LinguaLintBackend")

def translate_text(text, target_language, cultural_context):
    """Lingo CLI with Gemini - Use static i18n.json and test file"""
    if not text or target_language == 'en' or not text.strip():
        logger.info("Skipping translation due to empty text or English")
        return text
    
    try:
        lang_map = {'es': 'es', 'fr': 'fr', 'de': 'de', 'hi': 'hi', 'zh': 'zh', 'ja': 'ja', 'pt': 'pt', 'ru': 'ru', 'ar': 'ar'}
        lingo_lang = lang_map.get(target_language, target_language)
        
        full_text = text if cultural_context == 'neutral' else f"{text} ({cultural_context} context)"
        logger.info(f"🌐 Lingo-Gemini to {lingo_lang}: '{full_text[:30]}...'")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test file in temp dir
            source_path = os.path.join(temp_dir, 'test.js')
            with open(source_path, 'w') as f:
                f.write(f'const msg = "{full_text}";')  # Simple string for extraction
            
            # Static i18n.json path
            i18n_path = os.path.join(os.path.dirname(__file__), 'i18n.json')
            if not os.path.exists(i18n_path):
                logger.error(f"❌ i18n.json not found at {i18n_path}")
                return text
            
            env = os.environ.copy()
            google_key = os.getenv('GOOGLE_API_KEY') or os.getenv('GEMINI_API_KEY')
            if not google_key:
                logger.error("❌ No GOOGLE_API_KEY or GEMINI_API_KEY found")
                return text
            env['GOOGLE_API_KEY'] = google_key
            logger.info(f"✅ GOOGLE_API_KEY set, length={len(google_key)}")
            
            # Run Lingo in temp dir with static i18n.json
            steps = [
                ['npx', 'lingo.dev@latest', 'lockfile', '--cwd', temp_dir, '--config', i18n_path],
                ['npx', 'lingo.dev@latest', 'run', '--cwd', temp_dir, '--config', i18n_path, '--sourcePaths', source_path]
            ]
            for step, cmd in enumerate(steps):
                logger.debug(f"Lingo step {step}: {' '.join(cmd)}")
                result = subprocess.run(cmd, cwd=temp_dir, env=env, capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    logger.error(f"❌ Lingo step {step} failed: {result.stderr}")
                    return text
            
            # Parse output
            output_path = os.path.join(temp_dir, f'locales/{lingo_lang}.json')
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    output_data = json.load(f)
                    translated = output_data.get("msg", {}).get(lingo_lang, text)
                    if cultural_context != 'neutral' and f" ({cultural_context} context)" in translated:
                        translated = translated.replace(f" ({cultural_context} context)", "").strip()
                    if translated != text and translated.strip():
                        logger.info(f"✅ Lingo-Gemini success: '{text[:30]}...' -> '{translated[:30]}...'")
                        return translated
            
            logger.warning(f"No translation in {output_path}")
            return text
    
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Lingo CLI failed: {e.stderr}")
        return text
    except Exception as e:
        logger.error(f"❌ Lingo-Gemini error: {str(e)}")
        return text
# ------------ ENHANCED CODE ANALYSIS ------------

def enhanced_static_analysis(patch, filename):
    """Enhanced static code analysis with syntax error detection"""
    issues = []
    
    if not patch:
        return issues
    
    lines = patch.split("\n")
    added_lines = [line for line in lines if line.startswith("+") and not line.startswith("+++")]
    line_count = len(added_lines)
    
    # Get file extension for language-specific checks
    file_ext = filename.split('.')[-1] if '.' in filename else ''
    
    # Check 1: Syntax errors (NEW!)
    syntax_issues = check_syntax_errors(added_lines, file_ext, filename)
    issues.extend(syntax_issues)
    
    # Check 2: Large changes
    if line_count > 100:
        issues.append({
            "type": "code_length",
            "severity": "warning",
            "message": f"Large change detected: {line_count} lines added. Consider breaking into smaller PRs for easier review.",
            "filename": filename
        })
    
    # Check 3: Missing comments in significant changes
    comment_patterns = [r'^\+\s*(#|//|/\*|\*)', r'"""', r"'''"]
    comment_lines = sum(1 for line in added_lines if any(re.search(p, line) for p in comment_patterns))
    
    if comment_lines == 0 and line_count > 20:
        issues.append({
            "type": "missing_comments",
            "severity": "info",
            "message": "No comments found in significant code changes. Consider adding documentation for better maintainability.",
            "filename": filename
        })
    
    # Check 4: Debug statements
    debug_patterns = [
        r'console\.(log|debug|info|warn|error)',
        r'print\s*\(',
        r'debugger',
        r'System\.out\.print',
        r'var_dump',
        r'dd\('
    ]
    
    for line in added_lines:
        for pattern in debug_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append({
                    "type": "debug_code",
                    "severity": "warning",
                    "message": f"Debug statement found: {line.strip()[:60]}... Remove before merging.",
                    "filename": filename
                })
                break
    
    # Check 5: TODO/FIXME comments
    todo_pattern = r'(TODO|FIXME|HACK|XXX|BUG)'
    for line in added_lines:
        if re.search(todo_pattern, line, re.IGNORECASE):
            issues.append({
                "type": "todo_comment",
                "severity": "info",
                "message": f"TODO/FIXME comment found: {line.strip()[:80]}",
                "filename": filename
            })
            break
    
    # Check 6: Hardcoded credentials/secrets
    secret_patterns = [
        r'(password|passwd|pwd)\s*=\s*["\']',
        r'(api_key|apikey|secret|token)\s*=\s*["\']',
        r'(access_key|private_key)\s*=\s*["\']'
    ]
    
    for line in added_lines:
        for pattern in secret_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append({
                    "type": "security",
                    "severity": "error",
                    "message": "Potential hardcoded credential detected. Use environment variables instead.",
                    "filename": filename
                })
                break
    
    # Check 7: Long lines
    long_line_found = False
    for line in added_lines:
        clean_line = line[1:].rstrip()
        if len(clean_line) > 120 and not long_line_found:
            issues.append({
                "type": "code_style",
                "severity": "info",
                "message": f"Line exceeds 120 characters ({len(clean_line)} chars). Consider breaking it up for readability.",
                "filename": filename
            })
            long_line_found = True
            break
    
    # Check 8: Duplicate code patterns
    line_set = set()
    duplicates = 0
    for line in added_lines:
        clean = line.strip()
        if len(clean) > 20:
            if clean in line_set:
                duplicates += 1
            line_set.add(clean)
    
    if duplicates > 3:
        issues.append({
            "type": "code_duplication",
            "severity": "warning",
            "message": f"Potential code duplication detected ({duplicates} similar lines). Consider refactoring.",
            "filename": filename
        })
    
    return issues


def check_syntax_errors(added_lines, file_ext, filename):
    """Check for common syntax errors"""
    issues = []
    
    # Combine added lines into code string
    code_lines = [line[1:] if line.startswith('+') else line for line in added_lines]
    code = '\n'.join(code_lines)
    
    # Language-specific syntax checks
    if file_ext in ['py', 'python']:
        # Python syntax check
        try:
            import ast
            # Try to parse as Python code
            ast.parse(code)
        except SyntaxError as e:
            issues.append({
                "type": "syntax_error",
                "severity": "error",
                "message": f"Python syntax error: {str(e)}. Check line {e.lineno if hasattr(e, 'lineno') else 'unknown'}",
                "filename": filename
            })
        except Exception:
            # If code is incomplete (like just a function), check for common issues
            pass
        
        # Check for common Python mistakes
        for i, line in enumerate(code_lines, 1):
            # Unclosed parentheses/brackets
            open_count = line.count('(') + line.count('[') + line.count('{')
            close_count = line.count(')') + line.count(']') + line.count('}')
            if open_count > close_count:
                issues.append({
                    "type": "syntax_error",
                    "severity": "error",
                    "message": f"Unclosed parentheses/brackets on line: {line.strip()[:60]}...",
                    "filename": filename
                })
            
            # Missing colon after if/for/while/def/class
            if re.search(r'^\s*(if|for|while|def|class|elif|else|try|except|finally|with)\s+.+[^:]$', line.strip()):
                if not line.strip().endswith(':'):
                    issues.append({
                        "type": "syntax_error",
                        "severity": "error",
                        "message": f"Missing colon at end of line: {line.strip()[:60]}...",
                        "filename": filename
                    })
    
    elif file_ext in ['js', 'jsx', 'ts', 'tsx']:
        # JavaScript/TypeScript checks
        for i, line in enumerate(code_lines, 1):
            # Unclosed parentheses/brackets
            open_count = line.count('(') + line.count('[') + line.count('{')
            close_count = line.count(')') + line.count(']') + line.count('}')
            if open_count > close_count:
                issues.append({
                    "type": "syntax_error",
                    "severity": "error",
                    "message": f"Unclosed parentheses/brackets on line: {line.strip()[:60]}...",
                    "filename": filename
                })
            
            # Missing semicolon (optional but good practice)  
            if re.search(r'(var|let|const|return)\s+.+[^;{]$', line.strip()):
                if not line.strip().endswith((';', '{', '}')):
                    issues.append({
                        "type": "code_style",
                        "severity": "info",
                        "message": f"Consider adding semicolon: {line.strip()[:60]}...",
                        "filename": filename
                    })
    
    elif file_ext in ['java']:
        # Java checks
        for i, line in enumerate(code_lines, 1):
            # Missing semicolon
            if re.search(r'^\s*(int|String|boolean|float|double|return|System\.)', line) and not line.strip().endswith((';', '{', '}')):
                issues.append({
                    "type": "syntax_error",
                    "severity": "error",
                    "message": f"Missing semicolon: {line.strip()[:60]}...",
                    "filename": filename
                })
    
    # Universal checks for all languages
    for i, line in enumerate(code_lines, 1):
        # Mismatched quotes
        single_quotes = line.count("'") - line.count("\\'")
        double_quotes = line.count('"') - line.count('\\"')
        if single_quotes % 2 != 0 or double_quotes % 2 != 0:
            issues.append({
                "type": "syntax_error",
                "severity": "error",
                "message": f"Unclosed string literal on line: {line.strip()[:60]}...",
                "filename": filename
            })
    
    return issues


def ai_review_with_huggingface(code_content, filename):
    """Enhanced AI code review using HuggingFace"""
    if not code_content or not HUGGINGFACE_API_KEY:
        logger.warning(f"AI review skipped - content: {bool(code_content)}, api_key: {bool(HUGGINGFACE_API_KEY)}")
        return []
    
    try:
        model = "bigcode/starcoder"
        url = f"https://api-inference.huggingface.co/models/{model}"
        
        headers = {
            "Authorization": f"Bearer {HUGGINGFACE_API_KEY}",
            "Content-Type": "application/json"
        }
        
        truncated = code_content[:1000]
        
        prompt = f"""You are an expert code reviewer. Analyze this code VERY CAREFULLY for errors.

File: {filename}
Code:
```
{truncated}
```

CRITICAL: First check for SYNTAX ERRORS like:
- Unclosed parentheses, brackets, or quotes
- Missing semicolons or colons
- Mismatched braces
- Invalid syntax

Then provide 3-5 specific issues found:

Format each as:
- Category: [syntax_error/bug/quality/performance/security]
- Issue: [What is wrong - be specific]
- Suggestion: [Exact fix needed]

Focus on ACTUAL PROBLEMS, not style preferences.
"""

        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": 300,
                "temperature": 0.7,
                "top_p": 0.9,
                "do_sample": True,
                "return_full_text": False
            }
        }
        
        logger.info(f"Calling HuggingFace API for {filename}...")
        
        response = requests.post(url, json=payload, headers=headers, timeout=20)
        
        if response.status_code == 503:
            logger.warning("Model loading, retry...")
            time.sleep(3)
            response = requests.post(url, json=payload, headers=headers, timeout=20)
        
        if response.status_code != 200:
            logger.error(f"HuggingFace error {response.status_code}: {response.text}")
            return []
        
        result = response.json()
        suggestions = []
        
        if isinstance(result, list) and len(result) > 0:
            generated_text = result[0].get('generated_text', '')
            
            if generated_text:
                lines = generated_text.split('\n')
                current_suggestion = {}
                
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('```'):
                        continue
                    
                    if line.lower().startswith('- category:'):
                        if current_suggestion and 'message' in current_suggestion:
                            suggestions.append(current_suggestion)
                        current_suggestion = {
                            'type': 'ai_suggestion',
                            'filename': filename,
                            'severity': 'info',
                            'category': line.split(':', 1)[1].strip() if ':' in line else 'general'
                        }
                    elif line.lower().startswith('- issue:') and current_suggestion:
                        current_suggestion['message'] = line.split(':', 1)[1].strip() if ':' in line else line
                    elif line.lower().startswith('- suggestion:') and current_suggestion:
                        current_suggestion['suggestion'] = line.split(':', 1)[1].strip() if ':' in line else line
                
                if current_suggestion and 'message' in current_suggestion:
                    suggestions.append(current_suggestion)
                
                if not suggestions and generated_text:
                    suggestions.append({
                        'type': 'ai_suggestion',
                        'filename': filename,
                        'severity': 'info',
                        'category': 'general',
                        'message': generated_text[:200]
                    })
        
        logger.info(f"Generated {len(suggestions)} AI suggestions")
        return suggestions[:5]
        
    except requests.Timeout:
        logger.error("HuggingFace timeout")
        return []
    except Exception as e:
        logger.error(f"AI review error: {str(e)}")
        return []


# ------------ HELPER FUNCTIONS ------------

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
    except Exception as e:
        logger.error(f"Failed to save JSON to {path}: {e}")
        return False

def generate_id(prefix):
    return f"{prefix}_{secrets.token_hex(8)}"

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('gh_token')
        if not token:
            return jsonify({'logged_in': False, 'error': 'No token'}), 401
        
        users = load_json(USERS_FILE)
        user = next((u for u in users.values() if u.get('token') == token), None)
        
        if not user:
            return jsonify({'logged_in': False, 'error': 'Invalid token'}), 401
        
        request.user = user
        return f(*args, **kwargs)
    return decorated

def verify_webhook_signature(payload_body, signature_header):
    if not signature_header:
        return False
    mac = hmac.new(WEBHOOK_SECRET.encode(), msg=payload_body, digestmod=hashlib.sha256)
    return hmac.compare_digest("sha256=" + mac.hexdigest(), signature_header)

def store_oauth_state(state):
    states = load_json(OAUTH_STATES_FILE)
    states[state] = {
        'timestamp': datetime.utcnow().isoformat(),
        'used': False
    }
    save_json(OAUTH_STATES_FILE, states)

def validate_and_consume_oauth_state(state):
    if not state:
        return False
    
    states = load_json(OAUTH_STATES_FILE)
    
    if state not in states:
        return False
    
    state_data = states[state]
    
    if state_data.get('used'):
        return False
    
    try:
        timestamp = datetime.fromisoformat(state_data['timestamp'])
        age = (datetime.utcnow() - timestamp).total_seconds()
        if age > 600:
            del states[state]
            save_json(OAUTH_STATES_FILE, states)
            return False
    except:
        return False
    
    states[state]['used'] = True
    save_json(OAUTH_STATES_FILE, states)
    return True


# ------------ ROUTES ------------

@app.route("/api/auth/github")
def github_login():
    state = secrets.token_hex(16)
    store_oauth_state(state)
    
    redirect_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&scope=repo%20read:user%20user:email"
        f"&redirect_uri={APP_URL}/api/auth/github/callback"
        f"&state={state}"
    )
    
    return redirect(redirect_url)

@app.route("/api/auth/github/callback")
def github_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    
    if not code:
        return redirect(f"{FRONTEND_URL}?error=no_code")
    
    if not state or not validate_and_consume_oauth_state(state):
        return redirect(f"{FRONTEND_URL}?error=invalid_state")
    
    try:
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
        gh_token = token_data.get("access_token")
        
        if not gh_token:
            return redirect(f"{FRONTEND_URL}?error=token_failed")
        
        user_resp = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {gh_token}"},
            timeout=10
        )
        
        if user_resp.status_code != 200:
            return redirect(f"{FRONTEND_URL}?error=user_fetch_failed")
        
        user_data = user_resp.json()
        username = user_data.get("login")
        avatar = user_data.get("avatar_url")
        
        users = load_json(USERS_FILE)
        users[username] = {
            "username": username,
            "avatar": avatar,
            "token": gh_token,
            "repos": users.get(username, {}).get("repos", []),
            "configured_repos": users.get(username, {}).get("configured_repos", []),
            "repo_settings": users.get(username, {}).get("repo_settings", {})
        }
        save_json(USERS_FILE, users)
        
        resp = make_response(redirect(f"{FRONTEND_URL}/dashboard"))
        resp.set_cookie(
            'gh_token',
            gh_token,
            httponly=True,
            samesite='Lax',
            max_age=86400 * 30,
            path='/'
        )
        
        logger.info(f"Login successful: {username}")
        return resp
        
    except Exception as e:
        logger.error(f"OAuth error: {str(e)}")
        return redirect(f"{FRONTEND_URL}?error=server_error")

@app.route("/api/me")
def get_user():
    token = request.cookies.get('gh_token')
    if not token:
        return jsonify({"logged_in": False})
    
    users = load_json(USERS_FILE)
    user = next((u for u in users.values() if u.get("token") == token), None)
    
    if not user:
        return jsonify({"logged_in": False})
    
    return jsonify({
        "logged_in": True,
        "username": user["username"],
        "avatar": user["avatar"],
        "repos_count": len(user.get("repos", []))
    })

@app.route("/api/logout", methods=["POST"])
def logout():
    resp = make_response(jsonify({"success": True}))
    resp.set_cookie('gh_token', '', expires=0, path='/')
    return resp

@app.route("/api/repos")
@require_auth
def get_repos():
    try:
        resp = requests.get(
            "https://api.github.com/user/repos",
            headers={"Authorization": f"Bearer {request.user['token']}"},
            params={"per_page": 100, "sort": "updated"},
            timeout=10
        )
        
        if resp.status_code != 200:
            return jsonify({"error": "Failed to fetch repos"}), 500
        
        repos = resp.json()
        users = load_json(USERS_FILE)
        user_data = users.get(request.user["username"], {})
        configured_repos = user_data.get("configured_repos", [])
        
        formatted = [
            {
                "id": r["id"],
                "name": r["name"],
                "full_name": r["full_name"],
                "language": r.get("language"),
                "private": r.get("private", False),
                "webhook_configured": r["full_name"] in configured_repos
            }
            for r in repos
        ]
        
        if request.user["username"] in users:
            users[request.user["username"]]["repos"] = formatted
            save_json(USERS_FILE, users)
        
        return jsonify(formatted)
        
    except Exception as e:
        logger.error(f"Error fetching repos: {str(e)}")
        return jsonify({"error": "Server error"}), 500

@app.route("/api/repos/<path:repo_full_name>/webhook", methods=["POST"])
@require_auth
def setup_webhook(repo_full_name):
    try:
        data = request.get_json()
        language_preference = data.get("language", "en")
        cultural_context = data.get("cultural_context", "neutral")
        
        logger.info(f"Setting up webhook for {repo_full_name}")
        
        webhook_url = f"{APP_URL}/webhook"
        webhook_payload = {
            "name": "web",
            "active": True,
            "events": ["pull_request"],
            "config": {
                "url": webhook_url,
                "content_type": "json",
                "secret": WEBHOOK_SECRET,
                "insecure_ssl": "0"
            }
        }
        
        resp = requests.post(
            f"https://api.github.com/repos/{repo_full_name}/hooks",
            headers={
                "Authorization": f"Bearer {request.user['token']}",
                "Accept": "application/vnd.github+json"
            },
            json=webhook_payload,
            timeout=10
        )
        
        if resp.status_code in [201, 422]:
            users = load_json(USERS_FILE)
            if request.user["username"] in users:
                if "configured_repos" not in users[request.user["username"]]:
                    users[request.user["username"]]["configured_repos"] = []
                if "repo_settings" not in users[request.user["username"]]:
                    users[request.user["username"]]["repo_settings"] = {}
                
                if repo_full_name not in users[request.user["username"]]["configured_repos"]:
                    users[request.user["username"]]["configured_repos"].append(repo_full_name)
                
                users[request.user["username"]]["repo_settings"][repo_full_name] = {
                    "language": language_preference,
                    "cultural_context": cultural_context,
                    "webhook_id": resp.json().get("id") if resp.status_code == 201 else None
                }
                save_json(USERS_FILE, users)
            
            return jsonify({
                "success": True,
                "message": "Webhook configured successfully"
            })
        else:
            logger.error(f"Webhook failed: {resp.status_code} - {resp.text}")
            return jsonify({
                "success": False,
                "error": f"Failed to create webhook: {resp.text}"
            }), resp.status_code
            
    except Exception as e:
        logger.error(f"Error setting up webhook: {str(e)}")
        return jsonify({"error": "Server error"}), 500

@app.route("/api/reviews")
@require_auth
def get_reviews():
    reviews = load_json(REVIEWS_FILE)
    return jsonify(list(reviews.values()))

@app.route("/api/reviews/<review_id>/vote", methods=["POST"])
@require_auth
def vote_review(review_id):
    try:
        data = request.get_json()
        vote_type = data.get("type")
        
        if vote_type not in ["up", "down"]:
            return jsonify({"error": "Invalid vote type"}), 400
        
        reviews = load_json(REVIEWS_FILE)
        if review_id not in reviews:
            return jsonify({"error": "Review not found"}), 404
        
        review = reviews[review_id]
        if vote_type == "up":
            review["votes"]["upvotes"] += 1
        else:
            review["votes"]["downvotes"] += 1
        
        save_json(REVIEWS_FILE, reviews)
        
        for u in load_json(USERS_FILE).values():
            socketio.emit("update_review", review, room=f"user:{u['username']}")
        
        return jsonify({"success": True, "votes": review["votes"]})
        
    except Exception as e:
        logger.error(f"Vote error: {str(e)}")
        return jsonify({"error": "Server error"}), 500

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

@app.route("/webhook", methods=["POST"])
def webhook():
    signature = request.headers.get("X-Hub-Signature-256")
    payload_body = request.get_data()
    
    if not verify_webhook_signature(payload_body, signature):
        logger.warning("Invalid webhook signature")
        return jsonify({"error": "Invalid signature"}), 401
    
    payload = request.get_json()
    action = payload.get("action")
    
    logger.info(f"Webhook received: action={action}")
    
    if action not in ["opened", "synchronize", "reopened"]:
        logger.info(f"Ignoring action: {action}")
        return jsonify({"message": "Ignored action"}), 200
    
    pr = payload.get("pull_request", {})
    repo_name = payload.get("repository", {}).get("full_name")
    pr_number = pr.get("number")
    
    logger.info(f"Processing PR #{pr_number} in {repo_name}")
    
    # Find user who owns this repo
    users = load_json(USERS_FILE)
    repo_owner = repo_name.split("/")[0] if "/" in repo_name else None
    user = users.get(repo_owner)
    
    if not user:
        logger.error(f"No user found for repo owner: {repo_owner}")
        return jsonify({"error": "User not found"}), 404
    
    gh_token = user["token"]
    
    # Get repo settings
    repo_settings = user.get("repo_settings", {}).get(repo_name, {})
    target_language = repo_settings.get("language", "en")
    cultural_context = repo_settings.get("cultural_context", "neutral")
    
    logger.info(f"Repo settings: language={target_language}, cultural_context={cultural_context}")
    
    # Fetch PR files
    files_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/files"
    headers = {"Authorization": f"Bearer {gh_token}", "Accept": "application/vnd.github+json"}
    
    try:
        files_resp = requests.get(files_url, headers=headers, timeout=10)
        files_resp.raise_for_status()
        pr_files = files_resp.json()
        logger.info(f"Fetched {len(pr_files)} files from PR")
    except requests.RequestException as e:
        logger.error(f"Failed to fetch PR files: {str(e)}")
        pr_files = []
    
    # Prepare content
    pr_title = pr.get("title", "")
    pr_description = pr.get("body", "") or ""
    
    logger.info(f"Starting code analysis...")
    
    # Create review object
    review = {
        "id": generate_id("review"),
        "repo": repo_name,
        "pr_number": pr_number,
        "title": pr_title,
        "translated_title": pr_title,
        "description": pr_description,
        "translated_description": pr_description,
        "language": target_language,
        "cultural_context": cultural_context,
        "status": "processing",
        "timestamp": datetime.utcnow().isoformat(),
        "issues": [],
        "suggestions": [],
        "votes": {"upvotes": 0, "downvotes": 0}
    }
    
    # Analyze each file
    all_issues = []
    all_suggestions = []
    
    for file in pr_files[:10]:  # Limit to first 10 files
        patch = file.get("patch", "")
        filename = file.get("filename", "unknown")
        
        if not patch:
            continue
        
        logger.info(f"Analyzing file: {filename}")
        
        # 1. Enhanced static analysis
        file_issues = enhanced_static_analysis(patch, filename)
        all_issues.extend(file_issues)
        
        # 2. AI review (only for significant changes)
        if len(patch) > 100 and len(patch) < 5000:
            file_suggestions = ai_review_with_huggingface(patch, filename)
            all_suggestions.extend(file_suggestions)
    
    # Add to review BEFORE translation
    review["issues"] = all_issues
    review["suggestions"] = all_suggestions
    
    logger.info(f"Analysis complete: {len(all_issues)} issues, {len(all_suggestions)} suggestions")
    
    # 3. TRANSLATE EVERYTHING using the comprehensive function
    if target_language != 'en':
        review = translate_review_content(review, target_language, cultural_context)
    
    review["status"] = "completed"
    
    logger.info(f"✅ Review complete and translated")
    
    # Save review
    reviews = load_json(REVIEWS_FILE)
    reviews[review["id"]] = review
    save_json(REVIEWS_FILE, reviews)
    
    # Broadcast to all users via socket
    for u in users.values():
        try:
            socketio.emit("new_review", review, room=f"user:{u['username']}")
        except Exception as e:
            logger.error(f"Failed to emit to {u['username']}: {e}")
    
    logger.info(f"✅ Webhook processed for PR #{pr_number} in {repo_name}")
    return jsonify({"message": "Webhook processed", "review_id": review["id"]}), 200


# ------------ TEST ENDPOINTS ------------

@app.route("/api/test/translate", methods=["POST"])
def test_translation():
    """Test translation directly"""
    try:
        data = request.get_json()
        text = data.get("text", "Debug statement found. Remove before merging.")
        language = data.get("language", "hi")
        context = data.get("context", "Indian")
        
        logger.info(f"Testing translation: '{text}' to {language}")
        
        # Try translation
        translated = translate_text(text, language, context)
        
        # Check if Lingo CLI is available
        try:
            version_check = subprocess.run(
                ['npx', '-y', 'lingo.dev@latest', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            lingo_available = version_check.returncode == 0
            lingo_version = version_check.stdout.strip() if lingo_available else "Not available"
        except:
            lingo_available = False
            lingo_version = "Error checking version"
        
        return jsonify({
            "success": True,
            "original_text": text,
            "translated_text": translated,
            "target_language": language,
            "cultural_context": context,
            "translation_worked": translated != text,
            "lingo_cli_available": lingo_available,
            "lingo_version": lingo_version,
            "api_key_configured": bool(LINGODOTDEV_API_KEY),
            "api_key_length": len(LINGODOTDEV_API_KEY) if LINGODOTDEV_API_KEY else 0
        })
        
    except Exception as e:
        logger.error(f"Test translation failed: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500


@app.route("/api/test/lingo-cli", methods=["GET"])
def test_lingo_cli():
    """Test if Lingo CLI is working"""
    try:
        # Test 1: Check if npx is available
        npx_test = subprocess.run(
            ['npx', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        npx_available = npx_test.returncode == 0
        
        # Test 2: Check if lingo.dev package can be accessed
        lingo_test = subprocess.run(
            ['npx', '-y', 'lingo.dev@latest', '--help'],
            capture_output=True,
            text=True,
            timeout=30
        )
        lingo_available = lingo_test.returncode == 0
        
        # Test 3: Try a simple translation
        if LINGODOTDEV_API_KEY and lingo_available:
            translate_test = subprocess.run(
                [
                    'npx', '-y', 'lingo.dev@latest', 'translate',
                    'Hello world',
                    '--to', 'hi',
                    '--api-key', LINGODOTDEV_API_KEY
                ],
                capture_output=True,
                text=True,
                timeout=30
            )
            translation_works = translate_test.returncode == 0
            translation_output = translate_test.stdout.strip()
            translation_error = translate_test.stderr.strip()
        else:
            translation_works = False
            translation_output = "API key not configured or Lingo not available"
            translation_error = ""
        
        return jsonify({
            "npx_available": npx_available,
            "npx_version": npx_test.stdout.strip() if npx_available else npx_test.stderr.strip(),
            "lingo_cli_available": lingo_available,
            "lingo_help_output": lingo_test.stdout[:500] if lingo_available else lingo_test.stderr[:500],
            "api_key_configured": bool(LINGODOTDEV_API_KEY),
            "translation_test": {
                "works": translation_works,
                "output": translation_output,
                "error": translation_error
            }
        })
        
    except Exception as e:
        logger.error(f"CLI test failed: {str(e)}")
        return jsonify({
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500


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
    try:
        result = subprocess.run(['npx', '--version'], capture_output=True, timeout=5)
        npx_available = result.returncode == 0
    except:
        npx_available = False
    
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "npx_available": npx_available,
        "huggingface_configured": bool(HUGGINGFACE_API_KEY),
        "lingo_api_key_configured": bool(LINGODOTDEV_API_KEY)
    })

@app.route("/")
def root():
    return jsonify({
        "service": "LinguaLint API",
        "status": "running",
        "version": "4.0-corrected"
    })


# ------------ RUN ------------

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    logger.info(f"🚀 Starting LinguaLint Backend on port {port}")
    logger.info(f"APP_URL: {APP_URL}")
    logger.info(f"FRONTEND_URL: {FRONTEND_URL}")
    logger.info(f"HuggingFace API: {'✓ Configured' if HUGGINGFACE_API_KEY else '✗ Missing'}")
    logger.info(f"Lingo.dev API: {'✓ Configured' if LINGODOTDEV_API_KEY else '✗ Missing'}")
    
    # Check if Lingo CLI is available
    try:
        result = subprocess.run(['npx', '--version'], capture_output=True, timeout=5)
        lingo_available = result.returncode == 0
        logger.info(f"npx available: {'✓' if lingo_available else '✗'}")
    except:
        logger.warning("⚠️ npx not available - translation may not work")
    
    socketio.run(app, host="0.0.0.0", port=port, debug=True, allow_unsafe_werkzeug=True)