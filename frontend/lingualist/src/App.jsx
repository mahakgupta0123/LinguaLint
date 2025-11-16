// src/App.js
import Login from "./Login";
import RepoList from "./RepoList";
import LinguaLint from "./LinguaLint";

function App() {
  // const [user, setUser] = useState(null);
  // const [checking, setChecking] = useState(true);

  // useEffect(() => {
  //   // check /api/me which uses cookie
  //   api.get("/api/me")
  //     .then(res => {
  //       if (res.data && res.data.logged_in) {
  //         setUser({ username: res.data.username, avatar: res.data.avatar });
  //       } else {
  //         setUser(null);
  //       }
  //     })
  //     .catch(() => setUser(null))
  //     .finally(() => setChecking(false));
  // }, []);

  // if (checking) return <div>Checking auth...</div>;
  // if (!user) return <Login />;

  return (
    <div>
      {/* <header>
        <img src={user.avatar} alt="avatar" width="44" style={{borderRadius: 22}} />
        <span style={{marginLeft:8}}>Welcome, {user.username}</span>
        <button style={{marginLeft: 20}} onClick={() => {
          api.post("/api/logout").then(()=> window.location.reload());
        }}>Logout</button>
      </header>

      <main>
        <RepoList />
      </main> */}
      <LinguaLint/>
    </div>
  );
}

export default App;
