import React, { useEffect, useState, useCallback, useRef } from 'react';
import { io } from 'socket.io-client';
import { Github, LogOut, Code, FileText, ThumbsUp, ThumbsDown, CheckCircle, Clock, AlertCircle } from 'lucide-react';
import { Bar } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

const BACKEND_BASE = import.meta.env.VITE_BACKEND_URL ?? '';
const API = (path) => `${BACKEND_BASE}/api${path}`;

const SUPPORTED_LANGUAGES = [
  { code: 'en', name: 'English' },
  { code: 'es', name: 'Spanish' },
  { code: 'fr', name: 'French' },
  { code: 'de', name: 'German' },
  { code: 'hi', name: 'Hindi' },
  { code: 'zh', name: 'Chinese' },
  { code: 'ja', name: 'Japanese' },
  { code: 'pt', name: 'Portuguese' },
  { code: 'ru', name: 'Russian' },
  { code: 'ar', name: 'Arabic' }
];

const CULTURAL_CONTEXTS = [
  { value: 'neutral', label: 'Neutral (Technical)' },
  { value: 'Latin American', label: 'Latin American' },
  { value: 'European', label: 'European' },
  { value: 'Indian', label: 'Indian' },
  { value: 'formal', label: 'Formal (Professional)' },
  { value: 'casual', label: 'Casual (Friendly)' }
];

export default function App() {
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState(null);
  const [repos, setRepos] = useState([]);
  const [reviews, setReviews] = useState([]);
  const [analytics, setAnalytics] = useState({
    total_reviews: 0,
    issues_by_severity: {},
    issues_by_type: {},
    reviews_per_repo: {}
  });
  const [activeTab, setActiveTab] = useState('dashboard');
  const [notifications, setNotifications] = useState([]);
  const [error, setError] = useState(null);
  const [selectedRepo, setSelectedRepo] = useState(null);
  const [showWebhookModal, setShowWebhookModal] = useState(false);
  const [webhookConfig, setWebhookConfig] = useState({
    language: 'en',
    cultural_context: 'neutral'
  });
  const [showTranslated, setShowTranslated] = useState(true);
  
  const socketRef = useRef(null);
  const isConnectingRef = useRef(false);
  const hasCheckedAuthRef = useRef(false);

  const setupSocket = useCallback((username) => {
    if (!username || isConnectingRef.current) return;
    
    try {
      if (socketRef.current) {
        console.log('Disconnecting existing socket');
        socketRef.current.disconnect();
        socketRef.current = null;
      }
      
      isConnectingRef.current = true;
      
      const socketUrl = BACKEND_BASE || window.location.origin;
      console.log('Creating socket connection to:', socketUrl);
      
      const socket = io(socketUrl, {
        path: '/socket.io',
        transports: ['websocket', 'polling'],
        withCredentials: true,
        autoConnect: true,
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000
      });
      
      socket.on('connect', () => {
        console.log('Socket connected:', socket.id);
        socket.emit('join', { username });
        isConnectingRef.current = false;
      });
      
      socket.on('new_review', (review) => {
        console.log('New review received:', review);
        setReviews(prev => {
          if (prev.some(r => r.id === review.id)) return prev;
          return [review, ...prev];
        });
        setNotifications(prev => [{
          id: review.id,
          message: `New review for PR #${review.pr_number} in ${review.repo}`,
          timestamp: new Date().toISOString()
        }, ...prev]);
      });
      
      socket.on('update_review', (updatedReview) => {
        console.log('Review updated:', updatedReview);
        setReviews(prev => prev.map(r => r.id === updatedReview.id ? updatedReview : r));
      });
      
      socket.on('error', (err) => {
        console.error('Socket error:', err);
        isConnectingRef.current = false;
      });
      
      socket.on('disconnect', () => {
        console.log('Socket disconnected');
        isConnectingRef.current = false;
      });
      
      socketRef.current = socket;
      
    } catch (e) {
      console.error('Socket setup error:', e);
      isConnectingRef.current = false;
    }
  }, []);

  const fetchUser = useCallback(async () => {
    if (hasCheckedAuthRef.current) return;
    hasCheckedAuthRef.current = true;
    
    setLoading(true);
    setError(null);

    try {
      const r = await fetch(API('/me'), {
        credentials: 'include',
        headers: { 'Accept': 'application/json' }
      });
      const data = await r.json();
      console.log('User data:', data);

      if (data.logged_in) {
        setUser(data);
        setupSocket(data.username);
        await Promise.allSettled([
          fetchRepos(),
          fetchReviews(),
          fetchAnalytics()
        ]);
      } else {
        setUser(null);
      }
    } catch (e) {
      console.error('fetchUser error:', e);
      setError('Failed to fetch user data');
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, [setupSocket]);

  const fetchRepos = async () => {
    try {
      const r = await fetch(API('/repos'), {
        credentials: 'include',
        headers: { 'Accept': 'application/json' }
      });
      if (r.ok) {
        const data = await r.json();
        console.log('Repos fetched:', data.length);
        setRepos(data);
      } else {
        throw new Error(`HTTP ${r.status}`);
      }
    } catch (e) {
      console.error('fetchRepos error:', e);
      setError('Failed to fetch repositories');
    }
  };

  const fetchReviews = async () => {
    try {
      const r = await fetch(API('/reviews'), {
        credentials: 'include',
        headers: { 'Accept': 'application/json' }
      });
      if (r.ok) {
        const data = await r.json();
        console.log('Reviews fetched:', data.length);
        setReviews(data);
      } else {
        throw new Error(`HTTP ${r.status}`);
      }
    } catch (e) {
      console.error('fetchReviews error:', e);
      setError('Failed to fetch reviews');
    }
  };

  const fetchAnalytics = async () => {
    try {
      const r = await fetch(API('/analytics'), {
        credentials: 'include',
        headers: { 'Accept': 'application/json' }
      });
      if (r.ok) {
        const data = await r.json();
        setAnalytics(data);
      } else {
        throw new Error(`HTTP ${r.status}`);
      }
    } catch (e) {
      console.error('fetchAnalytics error:', e);
    }
  };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const errorParam = params.get('error');
    if (errorParam) {
      const errorMessages = {
        'no_code': 'GitHub did not provide authorization code',
        'missing_state': 'OAuth state parameter is missing',
        'invalid_state': 'OAuth state validation failed. Please try logging in again.',
        'token_failed': 'Failed to obtain access token from GitHub',
        'user_fetch_failed': 'Failed to fetch user information from GitHub',
        'network_error': 'Network error during authentication',
        'server_error': 'Server error during authentication'
      };
      setError(errorMessages[errorParam] || 'Authentication error occurred');
      setLoading(false);
      window.history.replaceState({}, '', window.location.pathname);
      return;
    }

    fetchUser();

    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
      }
    };
  }, [fetchUser]);

  const handleLogin = () => {
    const url = `${BACKEND_BASE || ''}/api/auth/github`;
    console.log('Redirecting to:', url);
    window.location.href = url;
  };

  const handleLogout = async () => {
    try {
      await fetch(API('/logout'), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Accept': 'application/json' }
      });
    } catch (e) {
      console.error('Logout error:', e);
    }

    setUser(null);
    setRepos([]);
    setReviews([]);
    setAnalytics({
      total_reviews: 0,
      issues_by_severity: {},
      issues_by_type: {},
      reviews_per_repo: {}
    });
    hasCheckedAuthRef.current = false;

    if (socketRef.current) {
      socketRef.current.disconnect();
      socketRef.current = null;
    }
  };

  const handleRepoSelect = (repo) => {
    console.log('Selected repo:', repo.name);
    setSelectedRepo(repo);
    if (!repo.webhook_configured) {
      setShowWebhookModal(true);
    } else {
      setActiveTab('reviews');
    }
  };

  const handleWebhookSetup = async () => {
    if (!selectedRepo) return;

    setError(null);
    
    try {
      const response = await fetch(API(`/repos/${selectedRepo.full_name}/webhook`), {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(webhookConfig)
      });

      const data = await response.json();
      if (response.ok) {
        setNotifications(prev => [{
          id: Date.now(),
          message: `Webhook configured for ${selectedRepo.name}! Language: ${webhookConfig.language}, Context: ${webhookConfig.cultural_context}`,
          timestamp: new Date().toISOString()
        }, ...prev]);
        setShowWebhookModal(false);
        await fetchRepos();
        setActiveTab('reviews');
      } else {
        setError(data.error || `Failed to configure webhook (HTTP ${response.status})`);
      }
    } catch (e) {
      console.error('Webhook setup error:', e);
      setError('Failed to configure webhook');
    }
  };

  const handleVote = async (reviewId, type) => {
    try {
      const response = await fetch(API(`/reviews/${reviewId}/vote`), {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ type })
      });

      const data = await response.json();
      if (response.ok) {
        setReviews(prev => prev.map(r => r.id === reviewId ? {
          ...r,
          votes: data.votes
        } : r));
      } else {
        console.error('Vote failed:', data.error);
      }
    } catch (e) {
      console.error('Vote error:', e);
    }
  };

  const dismissNotification = (notifId) => {
    setNotifications(prev => prev.filter(n => n.id !== notifId));
  };

  const severityChartData = {
    labels: Object.keys(analytics.issues_by_severity),
    datasets: [{
      label: 'Issues by Severity',
      data: Object.values(analytics.issues_by_severity),
      backgroundColor: ['#EF4444', '#F59E0B', '#10B981', '#3B82F6'],
      borderColor: ['#B91C1C', '#D97706', '#059669', '#1D4ED8'],
      borderWidth: 1
    }]
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
        <div className="text-white text-xl">Loading...</div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-4">
        <div className="max-w-md w-full bg-white/10 backdrop-blur-lg rounded-2xl shadow-2xl p-8 border border-white/20">
          <div className="text-center">
            <div className="inline-flex items-center justify-center w-20 h-20 bg-purple-500/20 rounded-full mb-6">
              <Code className="w-10 h-10 text-purple-300" />
            </div>
            <h1 className="text-3xl font-bold text-white mb-2">LinguaLint</h1>
            <p className="text-purple-200 mb-8">Automated multilingual code reviews powered by AI</p>
            {error && (
              <div className="mb-6 p-4 bg-red-500/20 border border-red-500/50 rounded-lg flex items-start gap-2">
                <AlertCircle className="w-5 h-5 text-red-300 flex-shrink-0 mt-0.5" />
                <p className="text-red-200 text-sm text-left">{error}</p>
              </div>
            )}
            <button
              onClick={handleLogin}
              className="w-full bg-white text-gray-900 font-semibold py-3 px-6 rounded-lg flex items-center justify-center gap-3 hover:bg-gray-100 transition-colors"
            >
              <Github className="w-5 h-5" /> Continue with GitHub
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      <header className="bg-white border-b border-gray-200 sticky top-0 z-50 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg flex items-center justify-center">
              <Code className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-gray-900">LinguaLint</h1>
              <p className="text-xs text-gray-500">Multilingual Analysis</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-3 px-4 py-2 bg-gray-50 rounded-lg">
              <img src={user.avatar} alt={user.username} className="w-8 h-8 rounded-full" />
              <div className="hidden sm:block">
                <p className="text-sm font-semibold text-gray-900">{user.username}</p>
                <p className="text-xs text-gray-500">{repos.length} repositories</p>
              </div>
            </div>
            <button
              onClick={handleLogout}
              className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
              title="Logout"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>
      </header>

      <nav className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex gap-8">
          {['dashboard', 'reviews', 'analytics'].map(tab => (
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
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        {error && (
          <div className="p-4 bg-red-100 border border-red-300 rounded-lg flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-red-600" />
            <p className="text-red-700 flex-1">{error}</p>
            <button onClick={() => setError(null)} className="text-red-500 hover:text-red-700">✕</button>
          </div>
        )}

        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200 flex justify-between items-center">
                <div>
                  <p className="text-sm text-gray-600">Total Reviews</p>
                  <p className="text-3xl font-bold text-gray-900">{analytics.total_reviews}</p>
                </div>
                <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center">
                  <FileText className="w-6 h-6 text-purple-600" />
                </div>
              </div>
              <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200 flex justify-between items-center">
                <div>
                  <p className="text-sm text-gray-600">Issues Found</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {Object.values(analytics.issues_by_severity).reduce((a, b) => a + b, 0)}
                  </p>
                </div>
                <div className="w-12 h-12 bg-red-100 rounded-lg flex items-center justify-center">
                  <AlertCircle className="w-6 h-6 text-red-600" />
                </div>
              </div>
              <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200 flex justify-between items-center">
                <div>
                  <p className="text-sm text-gray-600">Repositories</p>
                  <p className="text-3xl font-bold text-gray-900">{repos.length}</p>
                </div>
                <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                  <Code className="w-6 h-6 text-blue-600" />
                </div>
              </div>
            </div>

            <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Your Repositories</h2>
              {repos.length === 0 ? (
                <p className="text-gray-500 text-center py-8">No repositories found</p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {repos.map(repo => (
                    <button
                      key={repo.id}
                      onClick={() => handleRepoSelect(repo)}
                      className="p-4 rounded-lg border-2 border-gray-200 hover:border-purple-300 bg-white transition-all text-left"
                    >
                      <div className="flex items-start justify-between mb-2">
                        <span className="text-xs px-2 py-1 bg-gray-100 rounded text-gray-600">
                          {repo.language || 'Unknown'}
                        </span>
                        <div className="flex gap-1">
                          {repo.private && (
                            <span className="text-xs px-2 py-1 bg-yellow-100 rounded text-yellow-700">
                              Private
                            </span>
                          )}
                          {repo.webhook_configured && (
                            <span className="text-xs px-2 py-1 bg-green-100 rounded text-green-700">
                              ✓ Active
                            </span>
                          )}
                        </div>
                      </div>
                      <p className="font-semibold text-gray-900">{repo.name}</p>
                      <p className="text-sm text-gray-500 mt-1">{repo.full_name}</p>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'reviews' && (
          <div className="space-y-6">
            {reviews.length === 0 ? (
              <div className="bg-white rounded-xl shadow-sm p-12 border border-gray-200 text-center">
                <FileText className="w-16 h-16 text-gray-300 mx-auto mb-4" />
                <p className="text-gray-500 text-lg">No reviews yet</p>
                <p className="text-gray-400 text-sm mt-2">Reviews will appear here when pull requests are created</p>
              </div>
            ) : (
              reviews.map(review => (
                <div key={review.id} className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                  <div className="p-6 border-b border-gray-200 bg-gradient-to-r from-purple-50 to-pink-50">
                    <div className="flex justify-between items-start">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2 flex-wrap">
                          <span className="px-3 py-1 bg-purple-100 text-purple-700 rounded-full text-sm font-medium">
                            PR #{review.pr_number}
                          </span>
                          <span className={`px-3 py-1 rounded-full text-sm font-medium flex items-center gap-1 ${
                            review.status === 'completed' ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'
                          }`}>
                            <CheckCircle className="w-4 h-4" /> {review.status}
                          </span>
                          {review.language && review.language !== 'en' && (
                            <span className="px-3 py-1 bg-blue-100 text-blue-700 rounded-full text-sm font-medium">
                              {review.language.toUpperCase()}
                            </span>
                          )}
                        </div>
                        <h3 className="text-xl font-semibold text-gray-900 mb-1">
                          {showTranslated && review.translated_title && review.language !== 'en' 
                            ? review.translated_title 
                            : review.title}
                        </h3>
                        <p className="text-sm text-gray-600">{review.repo}</p>
                        {showTranslated && review.translated_title && review.language !== 'en' && (
                          <p className="text-xs text-gray-500 mt-1">
                            Translated to {SUPPORTED_LANGUAGES.find(l => l.code === review.language)?.name || review.language} 
                            {' '}({review.cultural_context})
                          </p>
                        )}
                      </div>
                      <div className="flex items-center gap-4 ml-4">
                        {review.language !== 'en' && review.translated_title && (
                          <button
                            onClick={() => setShowTranslated(!showTranslated)}
                            className="text-sm text-purple-600 hover:text-purple-800 whitespace-nowrap"
                          >
                            {showTranslated ? 'Show Original' : 'Show Translated'}
                          </button>
                        )}
                        <span className="text-sm text-gray-500 flex items-center gap-1 whitespace-nowrap">
                          <Clock className="w-4 h-4" />
                          {new Date(review.timestamp).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                    {review.description && (
                      <div className="mt-4">
                        <p className="text-gray-700">
                          {showTranslated && review.translated_description && review.language !== 'en'
                            ? review.translated_description 
                            : review.description}
                        </p>
                      </div>
                    )}
                  </div>

                  <div className="p-6 space-y-4">
                    {review.issues && review.issues.length > 0 ? (
                      <div>
                        <h4 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
                          <AlertCircle className="w-5 h-5 text-orange-500" />
                          Issues ({review.issues.length})
                        </h4>
                        <div className="space-y-2">
                          {review.issues.map((issue, idx) => (
                            <div key={idx} className="p-4 rounded-lg bg-gray-50 border border-gray-200">
                              <div className="flex items-center gap-2 mb-2">
                                <span className={`px-2 py-1 rounded text-xs font-medium border ${
                                  issue.severity === 'warning' ? 'bg-yellow-50 text-yellow-700 border-yellow-200' :
                                  issue.severity === 'error' ? 'bg-red-50 text-red-700 border-red-200' :
                                  'bg-blue-50 text-blue-700 border-blue-200'
                                }`}>
                                  {issue.severity?.toUpperCase() || 'INFO'}
                                </span>
                                <span className="text-sm text-gray-600 font-mono">{issue.filename || 'N/A'}</span>
                              </div>
                              <p className="text-gray-900">{issue.message}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-6">
                        <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-2" />
                        <p className="text-gray-600">No issues found! Code looks good. ✨</p>
                      </div>
                    )}

                    {review.suggestions && review.suggestions.length > 0 && (
                      <div>
                        <h4 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
                          💡 AI Suggestions ({review.suggestions.length})
                        </h4>
                        <div className="space-y-2">
                          {review.suggestions.map((s, i) => (
                            <div key={i} className="flex items-start gap-2 p-3 bg-blue-50 rounded-lg border border-blue-100">
                              <span className="text-blue-500 mt-1">→</span>
                              <div className="flex-1">
                                <p className="text-gray-800">{s.message}</p>
                                {s.filename && <p className="text-xs text-gray-500 mt-1 font-mono">{s.filename}</p>}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="mt-6 pt-6 border-t border-gray-200 flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <button
                          onClick={() => handleVote(review.id, 'up')}
                          className="flex items-center gap-2 px-4 py-2 bg-green-50 text-green-700 rounded-lg hover:bg-green-100 transition-colors"
                        >
                          <ThumbsUp className="w-4 h-4" /> {review.votes?.upvotes || 0}
                        </button>
                        <button
                          onClick={() => handleVote(review.id, 'down')}
                          className="flex items-center gap-2 px-4 py-2 bg-red-50 text-red-700 rounded-lg hover:bg-red-100 transition-colors"
                        >
                          <ThumbsDown className="w-4 h-4" /> {review.votes?.downvotes || 0}
                        </button>
                      </div>
                      <a
                        href={`https://github.com/${review.repo}/pull/${review.pr_number}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 px-4 py-2 bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors"
                      >
                        <Github className="w-4 h-4" /> View on GitHub
                      </a>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'analytics' && (
          <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200 space-y-6">
            <h2 className="text-lg font-semibold text-gray-900">Analytics Overview</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 className="text-md font-medium text-gray-700 mb-3">Issues by Severity</h3>
                {Object.keys(analytics.issues_by_severity).length > 0 ? (
                  <Bar
                    data={severityChartData}
                    options={{
                      responsive: true,
                      plugins: { 
                        legend: { position: 'top' }, 
                        title: { display: false } 
                      },
                      scales: { y: { beginAtZero: true } }
                    }}
                  />
                ) : (
                  <p className="text-gray-500 text-sm">No data available</p>
                )}
              </div>
              <div>
                <h3 className="text-md font-medium text-gray-700 mb-3">Issues by Type</h3>
                {Object.keys(analytics.issues_by_type).length > 0 ? (
                  <div className="space-y-2">
                    {Object.entries(analytics.issues_by_type).map(([type, count]) => (
                      <div key={type} className="flex justify-between items-center py-2 px-3 bg-gray-50 rounded border-b border-gray-100">
                        <span className="text-sm text-gray-700 capitalize">{type.replace('_', ' ')}</span>
                        <span className="text-sm font-semibold text-gray-900 bg-gray-200 px-2 py-1 rounded">{count}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-500 text-sm">No data available</p>
                )}
              </div>
            </div>
            <div>
              <h3 className="text-md font-medium text-gray-700 mb-3">Reviews per Repository</h3>
              {Object.keys(analytics.reviews_per_repo).length > 0 ? (
                <div className="space-y-2">
                  {Object.entries(analytics.reviews_per_repo).map(([repo, count]) => (
                    <div key={repo} className="flex justify-between items-center py-2 px-3 bg-gray-50 rounded border-b border-gray-100">
                      <span className="text-sm text-gray-700 font-mono">{repo}</span>
                      <span className="text-sm font-semibold text-gray-900 bg-purple-100 text-purple-700 px-2 py-1 rounded">{count}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No data available</p>
              )}
            </div>
          </div>
        )}
      </main>

      {notifications.length > 0 && (
        <div className="fixed top-20 right-4 z-50 w-80 space-y-2 max-h-[80vh] overflow-y-auto">
          {notifications.map(n => (
            <div
              key={n.id}
              className="bg-white rounded-lg shadow-lg p-4 border border-gray-200 flex justify-between items-start animate-slide-in"
            >
              <div className="flex-1">
                <p className="text-sm text-gray-900 font-medium">{n.message}</p>
                <p className="text-xs text-gray-500 mt-1">
                  {new Date(n.timestamp).toLocaleTimeString()}
                </p>
              </div>
              <button
                onClick={() => dismissNotification(n.id)}
                className="text-gray-400 hover:text-gray-700 ml-2 flex-shrink-0"
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      )}

      {showWebhookModal && selectedRepo && (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-2xl max-w-md w-full p-6">
            <h2 className="text-2xl font-bold text-gray-900 mb-4">
              Configure Review Settings
            </h2>
            <p className="text-gray-600 mb-6">
              Set up automated code reviews for <span className="font-semibold text-purple-600">{selectedRepo.name}</span>
            </p>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Review Language
                </label>
                <select
                  value={webhookConfig.language}
                  onChange={(e) => setWebhookConfig({ ...webhookConfig, language: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                >
                  {SUPPORTED_LANGUAGES.map(lang => (
                    <option key={lang.code} value={lang.code}>{lang.name}</option>
                  ))}
                </select>
                <p className="text-xs text-gray-500 mt-1">
                  Language for PR titles and descriptions
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Cultural Context
                </label>
                <select
                  value={webhookConfig.cultural_context}
                  onChange={(e) => setWebhookConfig({ ...webhookConfig, cultural_context: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                >
                  {CULTURAL_CONTEXTS.map(ctx => (
                    <option key={ctx.value} value={ctx.value}>{ctx.label}</option>
                  ))}
                </select>
                <p className="text-xs text-gray-500 mt-1">
                  How the AI should adapt translations and feedback
                </p>
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => {
                  setShowWebhookModal(false);
                  setSelectedRepo(null);
                }}
                className="flex-1 px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleWebhookSetup}
                className="flex-1 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors font-medium"
              >
                Configure Webhook
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}