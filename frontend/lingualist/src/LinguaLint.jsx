import React, { useEffect, useState } from 'react';
import { io } from 'socket.io-client';
import { Github, LogOut, Code, FileText, ThumbsUp, ThumbsDown } from 'lucide-react';

const BACKEND_BASE = import.meta.env.VITE_BACKEND_URL ?? ''; // empty when proxied by nginx
const API = (path) => `${BACKEND_BASE}/api${path}`;

// Socket initialization uses current origin when proxied, otherwise BACKEND_BASE
const socketUrl = BACKEND_BASE || window.location.origin;
const socket = io(socketUrl, {
  path: '/socket.io',
  transports: ['websocket'],
  withCredentials: true,
  autoConnect: false
});

export default function App() {
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState(null);
  const [repos, setRepos] = useState([]);
  const [reviews, setReviews] = useState([]);
  const [analytics, setAnalytics] = useState({ total_reviews: 0, issues_by_severity: {}, issues_by_type: {}, reviews_per_repo: {} });
  const [activeTab, setActiveTab] = useState('dashboard');
  const [notifications, setNotifications] = useState([]);

  useEffect(() => {
    (async () => { await fetchUser(); })();
    return () => {
      try { socket.disconnect(); } catch(e){}
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const setupSocketAfterLogin = (username) => {
    if (!username) return;
    if (!socket.connected) socket.connect();

    socket.off('connect');
    socket.on('connect', () => {
      console.log('socket connected', socket.id);
      socket.emit('join', { username });
    });

    socket.off('new_review');
    socket.on('new_review', (review) => {
      setReviews(prev => [review, ...prev]);
      setNotifications(prev => [{ id: review.id, message: `New review for PR #${review.pr_number} in ${review.repo}`, timestamp: new Date().toISOString() }, ...prev]);
    });
  };

  const fetchUser = async () => {
    setLoading(true);
    try {
      const r = await fetch(API('/me'), { credentials: 'include' });
      const data = await r.json();
      if (data.logged_in) {
        setUser(data);
        setupSocketAfterLogin(data.username);
        await Promise.all([fetchRepos(), fetchReviews(), fetchAnalytics()]);
      } else {
        setUser(null);
      }
    } catch (e) {
      console.error('fetchUser error', e);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const fetchRepos = async () => {
    try {
      const r = await fetch(API('/repos'), { credentials: 'include' });
      if (r.ok) setRepos(await r.json());
    } catch (e) { console.error(e); }
  };

  const fetchReviews = async () => {
    try {
      const r = await fetch(API('/reviews'), { credentials: 'include' });
      if (r.ok) setReviews(await r.json());
    } catch (e) { console.error(e); }
  };

  const fetchAnalytics = async () => {
    try {
      const r = await fetch(API('/analytics'), { credentials: 'include' });
      if (r.ok) setAnalytics(await r.json());
    } catch (e) { console.error(e); }
  };

  const handleLogin = () => {
    const url = `${BACKEND_BASE || ''}/api/auth/github`;
    window.location.href = url;
  };

  const handleLogout = () => {
    // backend has no logout endpoint in provided app.py — clear cookie client-side
    document.cookie = 'gh_token=; Max-Age=0; path=/; SameSite=Lax;';
    setUser(null);
    setRepos([]);
    setReviews([]);
    setAnalytics({ total_reviews: 0, issues_by_severity: {}, issues_by_type: {}, reviews_per_repo: {} });
    try { socket.disconnect(); } catch(e){}
  };

  const handleRepoSelect = (repo) => {
    setActiveTab('reviews');
  };

  const handleVote = (reviewId, type) => {
    setReviews(prev => prev.map(r => r.id === reviewId ? ({
      ...r,
      votes: {
        upvotes: type === 'up' ? r.votes.upvotes + 1 : r.votes.upvotes,
        downvotes: type === 'down' ? r.votes.downvotes + 1 : r.votes.downvotes
      }
    }) : r));
  };

  if (loading) return (<div className="min-h-screen flex items-center justify-center">Loading...</div>);

  if (!user) return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-4">
      <div className="max-w-md w-full bg-white/10 backdrop-blur-lg rounded-2xl shadow-2xl p-8 border border-white/20">
        <div className="text-center">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-purple-500/20 rounded-full mb-6">
            <Code className="w-10 h-10 text-purple-300" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Code Review AI</h1>
          <p className="text-purple-200 mb-8">Automated multilingual code reviews powered by AI</p>
          <button onClick={handleLogin} className="w-full bg-white text-gray-900 font-semibold py-3 px-6 rounded-lg flex items-center justify-center gap-3">
            <Github className="w-5 h-5" /> Continue with GitHub
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      <header className="bg-white border-b border-gray-200 sticky top-0 z-50 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
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
                <p className="text-xs text-gray-500">{repos.length} repositories</p>
              </div>
            </div>
            <button onClick={handleLogout} className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors">
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>
      </header>

      <nav className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex gap-8">
          {['dashboard', 'reviews', 'analytics'].map(tab => (
            <button key={tab} onClick={() => setActiveTab(tab)} className={`py-4 px-2 border-b-2 font-medium text-sm capitalize transition-colors ${activeTab === tab ? 'border-purple-500 text-purple-600' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'}`}>
              {tab}
            </button>
          ))}
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
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
                  <p className="text-3xl font-bold text-gray-900">{Object.values(analytics.issues_by_severity).reduce((a,b)=>a+b,0)}</p>
                </div>
                <div className="w-12 h-12 bg-red-100 rounded-lg flex items-center justify-center">
                  <FileText className="w-6 h-6 text-red-600" />
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
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Select Repository</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {repos.map(repo => (
                  <button key={repo.id} onClick={() => handleRepoSelect(repo)} className={`p-4 rounded-lg border-2 transition-all text-left ${/* eslint-disable-line */ ''} border-gray-200 hover:border-purple-300 bg-white`}>
                    <div className="flex items-start justify-between mb-2">
                      <span className="text-xs px-2 py-1 bg-gray-100 rounded text-gray-600">{repo.language || 'Unknown'}</span>
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
            {reviews.map(review => (
              <div key={review.id} className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <div className="p-6 border-b border-gray-200 bg-gradient-to-r from-purple-50 to-pink-50 flex justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <span className="px-3 py-1 bg-purple-100 text-purple-700 rounded-full text-sm font-medium">PR #{review.pr_number}</span>
                      <span className="px-3 py-1 bg-green-100 text-green-700 rounded-full text-sm font-medium flex items-center gap-1">
                        <CheckCircle className="w-4 h-4" /> {review.status}
                      </span>
                    </div>
                    <h3 className="text-xl font-semibold text-gray-900">{review.title}</h3>
                    <p className="text-sm text-gray-600">{review.repo}</p>
                  </div>
                  <div className="text-sm text-gray-500 flex items-center gap-1">
                    <Clock className="w-4 h-4" /> {new Date(review.timestamp).toLocaleDateString()}
                  </div>
                </div>

                <div className="p-6 space-y-4">
                  {review.issues?.map((issue, idx) => (
                    <div key={idx} className="p-4 rounded-lg bg-gray-50 border border-gray-200 flex gap-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <span className={`px-2 py-1 rounded text-xs font-medium border`}>{issue.severity?.toUpperCase()}</span>
                          <span className="text-sm text-gray-600">Line {issue.line}</span>
                        </div>
                        <p className="text-gray-900 font-medium mb-1">{issue.message}</p>
                      </div>
                    </div>
                  ))}

                  {review.suggestions?.length > 0 && (
                    <div>
                      <h4 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">💡 Suggestions</h4>
                      <ul className="space-y-2">
                        {review.suggestions.map((s, i) => <li key={i} className="flex items-start gap-2 text-gray-700"><span className="text-purple-500 mt-1">→</span>{s}</li>)}
                      </ul>
                    </div>
                  )}

                  <div className="mt-6 pt-6 border-t border-gray-200 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <button onClick={() => handleVote(review.id, 'up')} className="flex items-center gap-2 px-4 py-2 bg-green-50 text-green-700 rounded-lg hover:bg-green-100 transition-colors">
                        <ThumbsUp className="w-4 h-4" /> {review.votes?.upvotes || 0}
                      </button>
                      <button onClick={() => handleVote(review.id, 'down')} className="flex items-center gap-2 px-4 py-2 bg-red-50 text-red-700 rounded-lg hover:bg-red-100 transition-colors">
                        <ThumbsDown className="w-4 h-4" /> {review.votes?.downvotes || 0}
                      </button>
                    </div>
                    <a href={`https://github.com/${review.repo}/pull/${review.pr_number}`} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 px-4 py-2 bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors">
                      <Github className="w-4 h-4" /> View on GitHub
                    </a>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'analytics' && (
          <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200 space-y-6">
            <h2 className="text-lg font-semibold text-gray-900">Analytics</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 className="text-md font-medium text-gray-700 mb-2">Issues by Severity</h3>
                {Object.entries(analytics.issues_by_severity).map(([sev,count])=> (
                  <p key={sev} className="text-sm text-gray-600">{sev.charAt(0).toUpperCase()+sev.slice(1)}: {count}</p>
                ))}
              </div>
              <div>
                <h3 className="text-md font-medium text-gray-700 mb-2">Issues by Type</h3>
                {Object.entries(analytics.issues_by_type).map(([type,count])=> (
                  <p key={type} className="text-sm text-gray-600">{type.charAt(0).toUpperCase()+type.slice(1)}: {count}</p>
                ))}
              </div>
            </div>
          </div>
        )}
      </main>

      <div className="fixed top-16 right-4 z-50 w-80 space-y-2">
        {notifications.map(n => (
          <div key={n.id} className="bg-white rounded-lg shadow-lg p-4 border border-gray-200 flex justify-between items-center">
            <div>
              <p className="text-sm text-gray-900">{n.message}</p>
              <p className="text-xs text-gray-500">{new Date(n.timestamp).toLocaleTimeString()}</p>
            </div>
            <button onClick={() => setNotifications(notifications.filter(notif => notif.id !== n.id))} className="text-gray-400 hover:text-gray-700">✖</button>
          </div>
        ))}
      </div>
    </div>
  );
}

