import './App.css'

function App() {
  return (
    <main className="container">
      <div className="logo-badge" aria-hidden="true">
        🦅
      </div>
      <h1 className="title">STUDENT PHOENIX</h1>
      <p className="subtitle">Academic Operating Platform</p>

      <div className="divider" role="separator" />

      <div className="status-badge" role="status">
        <span className="status-dot" aria-hidden="true" />
        <span>Foundation initialized successfully.</span>
      </div>

      <p className="phase-tag">Phase 1 — Project Foundation</p>
    </main>
  )
}

export default App
