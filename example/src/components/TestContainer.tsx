import { useState } from 'react'

export interface TestResult {
  type: 'success' | 'error' | 'info'
  message: string
}

interface TestContainerProps {
  title: string
  description: string
  onRunTest: () => Promise<void>
  results: TestResult[]
  isRunning: boolean
}

const TestContainer: React.FC<TestContainerProps> = ({
  title,
  description,
  onRunTest,
  results,
  isRunning
}) => {
  return (
    <div className="test-container">
      <h2>{title}</h2>
      <p>{description}</p>
      
      <button 
        onClick={onRunTest} 
        disabled={isRunning}
        style={{ marginBottom: '1rem' }}
      >
        {isRunning ? 'Running...' : 'Run Test'}
      </button>
      
      <div className="results-container">
        {results.map((result, index) => (
          <div key={index} className={`test-result ${result.type}`}>
            {result.message}
          </div>
        ))}
      </div>
    </div>
  )
}

export default TestContainer
