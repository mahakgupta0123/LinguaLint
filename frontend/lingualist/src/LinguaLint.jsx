import React, { useState, useEffect } from 'react';
import { AlertCircle, CheckCircle, Clock, Globe, ThumbsUp, ThumbsDown, Github, LogOut, Settings, Code, FileText, TrendingUp } from 'lucide-react';

const LinguaLint = () => {
  const [user, setUser] = useState(null);
  const [repos, setRepos] = useState([]);
  const [selectedRepo, setSelectedRepo] = useState(null);
  const [reviews, setReviews] = useState([]);
  const [selectedLanguage, setSelectedLanguage] = useState('en');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard');

  // Mock data for demo
  const mockUser = {
    username: 'johndoe',
    avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=John',
    repos_count: 12
  };

  const mockRepos = [
    { id: 1, name: 'frontend-app', full_name: 'johndoe/frontend-app', language: 'JavaScript' },
    { id: 2, name: 'backend-api', full_name: 'johndoe/backend-api', language: 'Python' },
    { id: 3, name: 'mobile-app', full_name: 'johndoe/mobile-app', language: 'TypeScript' }
  ];

  const mockReviews = [
    {
      id: 'rev_001',
      pr_number: 42,
      repo: 'johndoe/frontend-app',
      title: 'Add user authentication',
      timestamp: '2025-11-14T10:30:00Z',
      status: 'completed',
      issues: [
        { line: 23, severity: 'high', type: 'security', message: 'Missing input validation for user credentials', translation: { hi: 'उपयोगकर्ता क्रेडेंशियल्स के लिए इनपुट सत्यापन गायब है', ja: 'ユーザー認証情報の入力検証が不足しています' } },
        { line: 45, severity: 'medium', type: 'performance', message: 'Consider using async/await instead of callbacks', translation: { hi: 'कॉलबैक के बजाय async/await का उपयोग करने पर विचार करें', ja: 'コールバックの代わりにasync/awaitの使用を検討してください' } }
      ],
      suggestions: ['Add password hashing with bcrypt', 'Implement rate limiting for login attempts'],
      votes: { upvotes: 5, downvotes: 1 },
      formality: { ja: 'formal', hi: 'neutral', es: 'casual' }
    },
    {
      id: 'rev_002',
      pr_number: 38,
      repo: 'johndoe/backend-api',
      title: 'Fix database connection leak',
      timestamp: '2025-11-13T15:20:00Z',
      status: 'completed',
      issues: [
        { line: 67, severity: 'high', type: 'bug', message: 'Database connection not closed in error handler', translation: { hi: 'त्रुटि हैंडलर में डेटाबेस कनेक्शन बंद नहीं', ja: 'エラーハンドラーでデータベース接続が閉じられていません' } }
      ],
      suggestions: ['Use context manager for database connections', 'Add connection pooling'],
      votes: { upvotes: 8, downvotes: 0 },
      formality: { ja: 'formal', hi: 'neutral', es: 'casual' }
    }
  ];

  const languages = [
    { code: 'en', name: 'English', flag: '🇬🇧' },
    { code: 'hi', name: 'हिंदी', flag: '🇮🇳' },
    { code: 'ja', name: '日本語', flag: '🇯🇵' },
    { code: 'es', name: 'Español', flag: '🇪🇸' },
    { code: 'fr', name: 'Français', flag: '🇫🇷' }
  ];

  useEffect(() => {
    // Simulate loading user data
    const token = localStorage.getItem('gh_token');
    if (token) {
      setUser(mockUser);
      setRepos(mockRepos);
      setReviews(mockReviews);
    }
  }, []);

  const handleLogin = () => {
    // In production: window.location.href = 'http://localhost:5000/auth/github';
    localStorage.setItem('gh_token', 'mock_token_12345');
    setUser(mockUser);
    setRepos(mockRepos);
    setReviews(mockReviews);
  };

  const handleLogout = () => {
    localStorage.removeItem('gh_token');
    setUser(null);
    setRepos([]);
    setReviews([]);
    setSelectedRepo(null);
  };

  const handleRepoSelect = (repo) => {
    setSelectedRepo(repo);
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
      setActiveTab('reviews');
    }, 1000);
  };

  const handleVote = (reviewId, voteType) => {
    setReviews(reviews.map(review => {
      if (review.id === reviewId) {
        return {
          ...review,
          votes: {
            upvotes: voteType === 'up' ? review.votes.upvotes + 1 : review.votes.upvotes,
            downvotes: voteType === 'down' ? review.votes.downvotes + 1 : review.votes.downvotes
          }
        };
      }
      return review;
    }));
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high': return 'bg-red-100 text-red-800 border-red-300';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-300';
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-300';
      default: return 'bg-gray-100 text-gray-800 border-gray-300';
    }
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'security': return '🔒';
      case 'bug': return '🐛';
      case 'performance': return '⚡';
      default: return '💡';
    }
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-white/10 backdrop-blur-lg rounded-2xl shadow-2xl p-8 border border-white/20">
          <div className="text-center">
            <div className="inline-flex items-center justify-center w-20 h-20 bg-purple-500/20 rounded-full mb-6">
              <Code className="w-10 h-10 text-purple-300" />
            </div>
            <h1 className="text-3xl font-bold text-white mb-2">Code Review AI</h1>
            <p className="text-purple-200 mb-8">Automated multilingual code reviews powered by AI</p>
            <button
              onClick={handleLogin}
              className="w-full bg-white hover:bg-gray-100 text-gray-900 font-semibold py-3 px-6 rounded-lg flex items-center justify-center gap-3 transition-all transform hover:scale-105"
            >
              <Github className="w-5 h-5" />
              Continue with GitHub
            </button>
            <p className="text-purple-300 text-sm mt-6">Secure OAuth authentication • No password required</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 sticky top-0 z-50 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg flex items-center justify-center">
                <Code className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">Code Review AI</h1>
                <p className="text-xs text-gray-500">Multilingual Analysis</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-3 px-4 py-2 bg-gray-50 rounded-lg">
                <img src={user.avatar} alt={user.username} className="w-8 h-8 rounded-full" />
                <div className="hidden sm:block">
                  <p className="text-sm font-semibold text-gray-900">{user.username}</p>
                  <p className="text-xs text-gray-500">{user.repos_count} repositories</p>
                </div>
              </div>
              <button
                onClick={handleLogout}
                className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <LogOut className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex gap-8">
            {['dashboard', 'reviews', 'analytics'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`py-4 px-2 border-b-2 font-medium text-sm capitalize transition-colors ${
                  activeTab === tab
                    ? 'border-purple-500 text-purple-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600">Total Reviews</p>
                    <p className="text-3xl font-bold text-gray-900 mt-1">{reviews.length}</p>
                  </div>
                  <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center">
                    <FileText className="w-6 h-6 text-purple-600" />
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600">Issues Found</p>
                    <p className="text-3xl font-bold text-gray-900 mt-1">
                      {reviews.reduce((acc, r) => acc + r.issues.length, 0)}
                    </p>
                  </div>
                  <div className="w-12 h-12 bg-red-100 rounded-lg flex items-center justify-center">
                    <AlertCircle className="w-6 h-6 text-red-600" />
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600">Languages</p>
                    <p className="text-3xl font-bold text-gray-900 mt-1">{languages.length}</p>
                  </div>
                  <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                    <Globe className="w-6 h-6 text-blue-600" />
                  </div>
                </div>
              </div>
            </div>

            {/* Repository Selection */}
            <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Select Repository</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {repos.map((repo) => (
                  <button
                    key={repo.id}
                    onClick={() => handleRepoSelect(repo)}
                    className={`p-4 rounded-lg border-2 transition-all text-left ${
                      selectedRepo?.id === repo.id
                        ? 'border-purple-500 bg-purple-50'
                        : 'border-gray-200 hover:border-purple-300 bg-white'
                    }`}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <Github className="w-5 h-5 text-gray-600" />
                      <span className="text-xs px-2 py-1 bg-gray-100 rounded text-gray-600">
                        {repo.language}
                      </span>
                    </div>
                    <p className="font-semibold text-gray-900">{repo.name}</p>
                    <p className="text-sm text-gray-500 mt-1">{repo.full_name}</p>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'reviews' && (
          <div className="space-y-6">
            {/* Language Selector */}
            <div className="bg-white rounded-xl shadow-sm p-4 border border-gray-200">
              <div className="flex items-center justify-between flex-wrap gap-4">
                <div className="flex items-center gap-3">
                  <Globe className="w-5 h-5 text-gray-600" />
                  <span className="font-medium text-gray-900">Translation:</span>
                </div>
                <div className="flex gap-2 flex-wrap">
                  {languages.map((lang) => (
                    <button
                      key={lang.code}
                      onClick={() => setSelectedLanguage(lang.code)}
                      className={`px-4 py-2 rounded-lg font-medium transition-all ${
                        selectedLanguage === lang.code
                          ? 'bg-purple-500 text-white'
                          : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                      }`}
                    >
                      <span className="mr-2">{lang.flag}</span>
                      {lang.name}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Reviews List */}
            {reviews.map((review) => (
              <div key={review.id} className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                {/* Review Header */}
                <div className="p-6 border-b border-gray-200 bg-gradient-to-r from-purple-50 to-pink-50">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <span className="px-3 py-1 bg-purple-100 text-purple-700 rounded-full text-sm font-medium">
                          PR #{review.pr_number}
                        </span>
                        <span className="px-3 py-1 bg-green-100 text-green-700 rounded-full text-sm font-medium flex items-center gap-1">
                          <CheckCircle className="w-4 h-4" />
                          {review.status}
                        </span>
                      </div>
                      <h3 className="text-xl font-semibold text-gray-900 mb-1">{review.title}</h3>
                      <p className="text-sm text-gray-600">{review.repo}</p>
                    </div>
                    <div className="text-right">
                      <div className="flex items-center gap-2 text-sm text-gray-500">
                        <Clock className="w-4 h-4" />
                        {new Date(review.timestamp).toLocaleDateString()}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Issues */}
                <div className="p-6">
                  <h4 className="font-semibold text-gray-900 mb-4 flex items-center gap-2">
                    <AlertCircle className="w-5 h-5 text-red-500" />
                    Issues Found ({review.issues.length})
                  </h4>
                  <div className="space-y-4">
                    {review.issues.map((issue, idx) => (
                      <div key={idx} className="p-4 rounded-lg bg-gray-50 border border-gray-200">
                        <div className="flex items-start gap-3">
                          <span className="text-2xl">{getTypeIcon(issue.type)}</span>
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-2">
                              <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(issue.severity)}`}>
                                {issue.severity.toUpperCase()}
                              </span>
                              <span className="text-sm text-gray-600">Line {issue.line}</span>
                            </div>
                            <p className="text-gray-900 font-medium mb-1">
                              {selectedLanguage === 'en' ? issue.message : issue.translation[selectedLanguage]}
                            </p>
                            {selectedLanguage !== 'en' && review.formality[selectedLanguage] && (
                              <span className="text-xs px-2 py-1 bg-blue-100 text-blue-700 rounded">
                                Tone: {review.formality[selectedLanguage]}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Suggestions */}
                  {review.suggestions.length > 0 && (
                    <div className="mt-6">
                      <h4 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
                        💡 Suggestions
                      </h4>
                      <ul className="space-y-2">
                        {review.suggestions.map((suggestion, idx) => (
                          <li key={idx} className="flex items-start gap-2 text-gray-700">
                            <span className="text-purple-500 mt-1">→</span>
                            <span>{suggestion}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Voting */}
                  <div className="mt-6 pt-6 border-t border-gray-200 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <button
                        onClick={() => handleVote(review.id, 'up')}
                        className="flex items-center gap-2 px-4 py-2 bg-green-50 text-green-700 rounded-lg hover:bg-green-100 transition-colors"
                      >
                        <ThumbsUp className="w-4 h-4" />
                        <span className="font-medium">{review.votes.upvotes}</span>
                      </button>
                      <button
                        onClick={() => handleVote(review.id, 'down')}
                        className="flex items-center gap-2 px-4 py-2 bg-red-50 text-red-700 rounded-lg hover:bg-red-100 transition-colors"
                      >
                        <ThumbsDown className="w-4 h-4" />
                        <span className="font-medium">{review.votes.downvotes}</span>
                      </button>
                    </div>
                    <a
                      href={`https://github.com/${review.repo}/pull/${review.pr_number}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 px-4 py-2 bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors"
                    >
                      <Github className="w-4 h-4" />
                      View on GitHub
                    </a>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'analytics' && (
          <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200">
            <div className="text-center py-12">
              <TrendingUp className="w-16 h-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-900 mb-2">Analytics Coming Soon</h3>
              <p className="text-gray-600">Track review trends, issue patterns, and team performance</p>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default LinguaLint;
