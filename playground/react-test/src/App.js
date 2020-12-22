import logo from './logo.svg';
import './App.css';
import { Authenticator, Negociator } from './TokenScript';

function App() {

  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <p>
          Edit <code>src/App.js</code> and save to reload.
        </p>
        <a
          className="App-link"
          href="https://reactjs.org"
          target="_blank"
          rel="noopener noreferrer"
        >
          <p>{Negociator.init()}</p>
          <p>{Authenticator.init()}</p>
        </a>
      </header>
    </div>
  );
}

export default App;
