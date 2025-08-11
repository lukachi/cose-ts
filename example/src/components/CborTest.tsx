import { useState } from 'react'
import TestContainer, { TestResult } from './TestContainer'
import { encodeMessageToCbor, decodeCborMessage } from '../cose-utils'

const CborTest = () => {
  const [results, setResults] = useState<TestResult[]>([])
  const [isRunning, setIsRunning] = useState(false)

  const addResult = (type: TestResult['type'], message: string) => {
    setResults(prev => [...prev, { type, message }])
  }

  const runTest = async () => {
    setIsRunning(true)
    setResults([])
    
    try {
      addResult('info', 'Testing CBOR encoding/decoding behavior')
      
      // Test 1: Simple object
      addResult('info', 'Test 1: Simple object')
      const simpleObj = { message: 'hello', number: 42 }
      const simpleEncoded = encodeMessageToCbor(simpleObj)
      const simpleDecoded = decodeCborMessage(simpleEncoded)
      addResult('success', `Simple object: ${JSON.stringify(simpleObj)} -> ${JSON.stringify(simpleDecoded)}`)
      
      // Test 2: Object with Buffer
      addResult('info', 'Test 2: Object with Buffer')
      const testBuffer = Buffer.from('test-data', 'utf-8')
      addResult('info', `Buffer type: ${typeof testBuffer}`)
      addResult('info', `Buffer constructor: ${testBuffer.constructor.name}`)
      addResult('info', `Buffer instanceof check: ${testBuffer instanceof Buffer}`)
      addResult('info', `Buffer data: [${Array.from(testBuffer).join(', ')}]`)
      addResult('info', `Buffer JSON: ${JSON.stringify(testBuffer)}`)
      
      const objWithBuffer = { 
        message: 'hello',
        buffer: testBuffer,
        kid: Buffer.from('customer:test', 'utf-8')
      }
      addResult('info', `Object with Buffer: ${JSON.stringify(objWithBuffer)}`)
      
      const bufferEncoded = encodeMessageToCbor(objWithBuffer)
      addResult('info', `Encoded hex: ${bufferEncoded.toString('hex')}`)
      
      const bufferDecoded = decodeCborMessage(bufferEncoded)
      addResult('success', `Buffer object: ${JSON.stringify(objWithBuffer)} -> ${JSON.stringify(bufferDecoded)}`)
      
      // Test 3: Nested structure like COSE headers
      addResult('info', 'Test 3: COSE-like headers structure')
      const coseHeaders = {
        unprotected: {
          kid: Buffer.from('customer:550e8400-e29b-41d4-a716-446655440000', 'utf-8')
        }
      }
      addResult('info', `COSE headers: ${JSON.stringify(coseHeaders)}`)
      
      const coseEncoded = encodeMessageToCbor(coseHeaders)
      addResult('info', `COSE encoded hex: ${coseEncoded.toString('hex')}`)
      
      const coseDecoded = decodeCborMessage(coseEncoded)
      addResult('success', `COSE headers: ${JSON.stringify(coseHeaders)} -> ${JSON.stringify(coseDecoded)}`)
      
      // Test 4: Check if Buffer is properly encoded as bytes
      addResult('info', 'Test 4: Buffer byte encoding verification')
      const kidBuffer = Buffer.from('customer:test', 'utf-8')
      const kidEncoded = encodeMessageToCbor(kidBuffer)
      addResult('info', `Kid buffer encoded: ${kidEncoded.toString('hex')}`)
      const kidDecoded = decodeCborMessage(kidEncoded)
      addResult('info', `Kid decoded type: ${typeof kidDecoded}`)
      addResult('info', `Kid decoded constructor: ${kidDecoded?.constructor?.name || 'undefined'}`)
      addResult('success', `Kid buffer decoded: ${JSON.stringify(kidDecoded)}`)
      
      if (kidDecoded instanceof Uint8Array || (typeof Buffer !== 'undefined' && kidDecoded instanceof Buffer)) {
        addResult('success', '✅ Buffer correctly encoded as byte string!')
        addResult('info', `Decoded as bytes: [${Array.from(kidDecoded).join(', ')}]`)
        addResult('info', `Decoded as string: ${Buffer.from(kidDecoded).toString('utf-8')}`)
      } else {
        addResult('error', '❌ Buffer NOT encoded as byte string!')
      }
      
    } catch (error) {
      addResult('error', `Error: ${error instanceof Error ? error.message : String(error)}`)
      if (error instanceof Error && error.stack) {
        addResult('error', `Stack: ${error.stack}`)
      }
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <TestContainer
      title="CBOR Encoding Test"
      description="Tests CBOR encoding and decoding behavior with different data types, especially Buffer handling in browser environment."
      onRunTest={runTest}
      results={results}
      isRunning={isRunning}
    />
  )
}

export default CborTest
