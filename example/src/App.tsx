import { useState } from 'react'
import './App.css'
import BuildRequestTest from './components/BuildRequestTest'
import CborTest from './components/CborTest'

function App() {
  const [activeTest, setActiveTest] = useState<'build' | 'cbor'>('cbor')

  return (
    <div className="app">
      <header className="app-header">
        <h1>COSE Implementation Test Suite</h1>
        <p>Testing Typescript COSE implementation in browser environment</p>
        
        <div className="test-selector">
          <button 
            className={activeTest === 'cbor' ? 'active' : ''}
            onClick={() => setActiveTest('cbor')}
          >
            CBOR Test
          </button>
          <button 
            className={activeTest === 'build' ? 'active' : ''}
            onClick={() => setActiveTest('build')}
          >
            Build Request Test
          </button>
        </div>
      </header>

      <main className="app-main">
        {activeTest === 'cbor' && <CborTest />}
        {activeTest === 'build' && <BuildRequestTest />}
      </main>
    </div>
  )
}

export default App
