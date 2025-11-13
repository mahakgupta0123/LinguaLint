"""
Demo data generator for testing without GitHub integration
Use this when testing locally or for hackathon presentations
"""

import json
import secrets
from datetime import datetime, timedelta

def generate_demo_data():
    """Generate complete demo dataset"""
    
    # Demo users
    users = {
        "user_demo123": {
            "id": "user_demo123",
            "username": "demo_developer",
            "github_id": 12345,
            "avatar": "https://api.dicebear.com/7.x/avataaars/svg?seed=Demo",
            "token": "demo_token_" + secrets.token_hex(8),
            "created_at": datetime.now().isoformat(),
            "repos": [
                {
                    "repo_id": 1,
                    "full_name": "demo/frontend-app",
                    "webhook_id": "hook_123",
                    "created_at": datetime.now().isoformat()
                }
            ],
            "review_count": 5,
            "preferences": {
                "language": "en",
                "detail_level": "high",
                "preferred_languages": ["hi", "ja"]
            },
            "history": {
                "common_issues": ["missing_null_checks", "hardcoded_strings", "async_await"],
                "total_upvotes": 23,
                "total_downvotes": 2
            }
        }
    }
    
    # Demo reviews
    reviews = {
        "rev_demo001": {
            "id": "rev_demo001",
            "pr_number": 42,
            "repo": "demo/frontend-app",
            "title": "Add user authentication system",
            "author": "demo_developer",
            "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
            "status": "completed",
            "issues": [
                {
                    "line": 23,
                    "severity": "high",
                    "type": "security",
                    "message": "Missing input validation for user credentials. Attackers could inject malicious code through login forms.",
                    "suggestion": "Use a validation library like Joi or Yup to sanitize inputs",
                    "translation": {
                        "hi": "उपयोगकर्ता क्रेडेंशियल्स के लिए इनपुट सत्यापन गायब है। हमलावर लॉगिन फ़ॉर्म के माध्यम से दुर्भावनापूर्ण कोड इंजेक्ट कर सकते हैं।",
                        "ja": "ユーザー認証情報の入力検証が不足しています。攻撃者がログインフォームを通じて悪意のあるコードを注入する可能性があります。",
                        "es": "Falta la validación de entrada para las credenciales de usuario. Los atacantes podrían inyectar código malicioso a través de formularios de inicio de sesión.",
                        "fr": "Validation d'entrée manquante pour les informations d'identification de l'utilisateur. Les attaquants pourraient injecter du code malveillant via les formulaires de connexion."
                    }
                },
                {
                    "line": 45,
                    "severity": "medium",
                    "type": "performance",
                    "message": "Using nested callbacks creates callback hell. Consider using async/await for better readability and error handling.",
                    "suggestion": "Refactor to: async function handleLogin() { try { await validateUser(); } catch(e) { handleError(e); } }",
                    "translation": {
                        "hi": "नेस्टेड कॉलबैक का उपयोग कॉलबैक हेल बनाता है। बेहतर पठनीयता और त्रुटि हैंडलिंग के लिए async/await का उपयोग करने पर विचार करें।",
                        "ja": "ネストされたコールバックを使用するとコールバック地獄が発生します。より良い可読性とエラー処理のためにasync/awaitの使用を検討してください。",
                        "es": "El uso de callbacks anidados crea un infierno de callbacks. Considera usar async/await para una mejor legibilidad y manejo de errores.",
                        "fr": "L'utilisation de callbacks imbriqués crée un enfer de callbacks. Envisagez d'utiliser async/await pour une meilleure lisibilité et gestion des erreurs."
                    }
                },
                {
                    "line": 67,
                    "severity": "medium",
                    "type": "i18n",
                    "message": "Hardcoded error message 'Invalid credentials'. Should use translation keys for internationalization.",
                    "suggestion": "Replace with: t('errors.invalidCredentials') using i18next or similar",
                    "translation": {
                        "hi": "हार्डकोडेड त्रुटि संदेश 'अमान्य क्रेडेंशियल्स'। अंतर्राष्ट्रीयकरण के लिए अनुवाद कुंजियों का उपयोग करना चाहिए।",
                        "ja": "ハードコーディングされたエラーメッセージ「無効な認証情報」。国際化のために翻訳キーを使用する必要があります。",
                        "es": "Mensaje de error hardcoded 'Credenciales no válidas'. Debería usar claves de traducción para la internacionalización.",
                        "fr": "Message d'erreur codé en dur 'Identifiants invalides'. Devrait utiliser des clés de traduction pour l'internationalisation."
                    }
                },
                {
                    "line": 89,
                    "severity": "low",
                    "type": "best_practice",
                    "message": "Console.log statement found in production code. Use a proper logging library.",
                    "suggestion": "Replace with winston or pino logger",
                    "translation": {
                        "hi": "प्रोडक्शन कोड में Console.log स्टेटमेंट मिला। उचित लॉगिंग लाइब्रेरी का उपयोग करें।",
                        "ja": "本番コードにConsole.logステートメントが見つかりました。適切なロギングライブラリを使用してください。",
                        "es": "Se encontró una declaración console.log en el código de producción. Use una biblioteca de registro adecuada.",
                        "fr": "Instruction console.log trouvée dans le code de production. Utilisez une bibliothèque de journalisation appropriée."
                    }
                }
            ],
            "static_analysis": [
                {
                    "tool": "flake8",
                    "line": 34,
                    "message": "E501 line too long (95 > 79 characters)",
                    "severity": "low"
                },
                {
                    "tool": "flake8",
                    "line": 56,
                    "message": "F841 local variable 'result' is assigned but never used",
                    "severity": "medium"
                }
            ],
            "suggestions": [
                "Add password hashing using bcrypt with salt rounds of 10",
                "Implement rate limiting for login attempts (5 attempts per 15 minutes)",
                "Add JWT token expiration and refresh token mechanism",
                "Consider implementing OAuth2.0 for third-party authentication"
            ],
            "votes": {"upvotes": 8, "downvotes": 1},
            "formality": {
                "ja": "formal",
                "hi": "neutral",
                "es": "casual",
                "fr": "formal"
            },
            "context": {
                "commit_messages": [
                    "Add basic login form",
                    "Implement authentication logic",
                    "Fix validation issues"
                ],
                "files_changed": 5,
                "lines_added": 234,
                "lines_removed": 12
            }
        },
        "rev_demo002": {
            "id": "rev_demo002",
            "pr_number": 38,
            "repo": "demo/backend-api",
            "title": "Fix database connection leak in user service",
            "author": "demo_developer",
            "timestamp": (datetime.now() - timedelta(days=1)).isoformat(),
            "status": "completed",
            "issues": [
                {
                    "line": 67,
                    "severity": "high",
                    "type": "bug",
                    "message": "Database connection not properly closed in error handler. This will cause connection pool exhaustion under load.",
                    "suggestion": "Use context manager: with get_db_connection() as conn:",
                    "translation": {
                        "hi": "त्रुटि हैंडलर में डेटाबेस कनेक्शन ठीक से बंद नहीं हुआ। यह लोड के तहत कनेक्शन पूल थकावट का कारण बनेगा।",
                        "ja": "エラーハンドラーでデータベース接続が適切に閉じられていません。これにより負荷時に接続プールが枯渇します。",
                        "es": "La conexión a la base de datos no se cierra correctamente en el manejador de errores. Esto causará agotamiento del grupo de conexiones bajo carga.",
                        "fr": "La connexion à la base de données n'est pas correctement fermée dans le gestionnaire d'erreurs. Cela causera l'épuisement du pool de connexions sous charge."
                    }
                },
                {
                    "line": 92,
                    "severity": "high",
                    "type": "security",
                    "message": "SQL query vulnerable to injection. User input directly concatenated into query string.",
                    "suggestion": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                    "translation": {
                        "hi": "SQL क्वेरी इंजेक्शन के लिए संवेदनशील है। उपयोगकर्ता इनपुट सीधे क्वेरी स्ट्रिंग में जोड़ा गया है।",
                        "ja": "SQLクエリがインジェクションに対して脆弱です。ユーザー入力がクエリ文字列に直接連結されています。",
                        "es": "Consulta SQL vulnerable a inyección. La entrada del usuario se concatena directamente en la cadena de consulta.",
                        "fr": "Requête SQL vulnérable à l'injection. L'entrée utilisateur est directement concaténée dans la chaîne de requête."
                    }
                }
            ],
            "static_analysis": [
                {
                    "tool": "flake8",
                    "line": 67,
                    "message": "E722 do not use bare 'except'",
                    "severity": "medium"
                }
            ],
            "suggestions": [
                "Implement connection pooling with max_connections=20",
                "Add database transaction rollback on errors",
                "Use an ORM like SQLAlchemy for safer query building",
                "Add database connection health checks"
            ],
            "votes": {"upvotes": 12, "downvotes": 0},
            "formality": {
                "ja": "formal",
                "hi": "neutral",
                "es": "casual",
                "fr": "formal"
            },
            "context": {
                "commit_messages": [
                    "Fix connection leak",
                    "Add proper cleanup"
                ],
                "files_changed": 2,
                "lines_added": 45,
                "lines_removed": 23
            }
        },
        "rev_demo003": {
            "id": "rev_demo003",
            "pr_number": 51,
            "repo": "demo/frontend-app",
            "title": "Add dark mode toggle",
            "author": "demo_developer",
            "timestamp": (datetime.now() - timedelta(hours=6)).isoformat(),
            "status": "completed",
            "issues": [
                {
                    "line": 12,
                    "severity": "low",
                    "type": "accessibility",
                    "message": "Dark mode toggle missing ARIA labels. Screen readers won't understand the purpose.",
                    "suggestion": "Add: aria-label='Toggle dark mode' role='switch' aria-checked={isDark}",
                    "translation": {
                        "hi": "डार्क मोड टॉगल में ARIA लेबल गायब हैं। स्क्रीन रीडर्स उद्देश्य को नहीं समझेंगे।",
                        "ja": "ダークモードトグルにARIAラベルがありません。スクリーンリーダーは目的を理解できません。",
                        "es": "Al toggle de modo oscuro le faltan etiquetas ARIA. Los lectores de pantalla no entenderán el propósito.",
                        "fr": "Le basculement du mode sombre manque d'étiquettes ARIA. Les lecteurs d'écran ne comprendront pas le but."
                    }
                },
                {
                    "line": 34,
                    "severity": "medium",
                    "type": "performance",
                    "message": "Theme preference not persisted. User selection will be lost on page refresh.",
                    "suggestion": "Save to localStorage: localStorage.setItem('theme', theme)",
                    "translation": {
                        "hi": "थीम वरीयता संरक्षित नहीं है। पेज रीफ्रेश पर उपयोगकर्ता चयन खो जाएगा।",
                        "ja": "テーマの設定が保持されていません。ページ更新時にユーザーの選択が失われます。",
                        "es": "La preferencia de tema no se persiste. La selección del usuario se perderá al actualizar la página.",
                        "fr": "La préférence de thème n'est pas persistée. La sélection de l'utilisateur sera perdue lors de l'actualisation de la page."
                    }
                }
            ],
            "static_analysis": [],
            "suggestions": [
                "Respect system dark mode preference using prefers-color-scheme",
                "Add smooth transition when switching themes",
                "Ensure sufficient color contrast in dark mode (WCAG AA)"
            ],
            "votes": {"upvotes": 5, "downvotes": 0},
            "formality": {
                "ja": "casual",
                "hi": "neutral",
                "es": "casual",
                "fr": "casual"
            },
            "context": {
                "commit_messages": [
                    "Add dark mode CSS",
                    "Create toggle component"
                ],
                "files_changed": 3,
                "lines_added": 78,
                "lines_removed": 5
            }
        }
    }
    
    # Demo translations cache
    translations = {
        "Missing input validation": {
            "en": "Missing input validation",
            "hi": "इनपुट सत्यापन गायब है",
            "ja": "入力検証が不足しています",
            "es": "Falta validación de entrada",
            "fr": "Validation d'entrée manquante"
        },
        "Use async/await": {
            "en": "Use async/await",
            "hi": "async/await का उपयोग करें",
            "ja": "async/awaitを使用してください",
            "es": "Usa async/await",
            "fr": "Utilisez async/await"
        }
    }
    
    # Demo repositories
    repos = [
        {
            "id": 1,
            "name": "frontend-app",
            "full_name": "demo/frontend-app",
            "language": "JavaScript",
            "private": False,
            "description": "React frontend application"
        },
        {
            "id": 2,
            "name": "backend-api",
            "full_name": "demo/backend-api",
            "language": "Python",
            "private": False,
            "description": "Flask REST API"
        },
        {
            "id": 3,
            "name": "mobile-app",
            "full_name": "demo/mobile-app",
            "language": "TypeScript",
            "private": False,
            "description": "React Native mobile app"
        }
    ]
    
    return {
        "users": users,
        "reviews": reviews,
        "translations": translations,
        "repos": repos
    }


def save_demo_data():
    """Save demo data to JSON files"""
    data = generate_demo_data()
    
    # Save each dataset
    with open('data/users.json', 'w') as f:
        json.dump(data['users'], f, indent=2)
    
    with open('data/reviews.json', 'w') as f:
        json.dump(data['reviews'], f, indent=2)
    
    with open('data/translations.json', 'w') as f:
        json.dump(data['translations'], f, indent=2)
    
    print("✅ Demo data generated successfully!")
    print(f"   - {len(data['users'])} users")
    print(f"   - {len(data['reviews'])} reviews")
    print(f"   - {len(data['translations'])} translation entries")


if __name__ == "__main__":
    save_demo_data()
