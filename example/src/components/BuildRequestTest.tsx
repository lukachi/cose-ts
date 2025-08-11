import { useState } from 'react'
import TestContainer, { TestResult } from './TestContainer'
import { blockstream, kid, adminPK, hsmPK, encodeMessageToCbor, decodeCborMessage, signMessage, verifyMessage, deriveSharedKey } from '../cose-utils'
import { encrypt } from '@lukachi/cose-ts'
import { p256 } from '@noble/curves/nist'

const BuildRequestTest = () => {
  const [results, setResults] = useState<TestResult[]>([])
  const [isRunning, setIsRunning] = useState(false)

  const addResult = (type: TestResult['type'], message: string) => {
    setResults(prev => [...prev, { type, message }])
  }

  const runTest = async () => {
    console.log('here')
    setIsRunning(true)
    setResults([])
    
    try {
      addResult('info', 'Starting Build Request Test...')
      
      addResult('info', 'Step 1: Creating original message')
      const originalMessage = { 'action': 'get', 'resource': '/users' }
      addResult('success', `Original message: ${JSON.stringify(originalMessage)}`)
      
      addResult('info', 'Step 2: CBOR encoding message')
      const cborMsg = encodeMessageToCbor(originalMessage)
      addResult('success', `CBOR encoded message length: ${cborMsg.length}`)
      
      const decodedBack = decodeCborMessage(cborMsg)
      addResult('success', `CBOR decoded back: ${JSON.stringify(decodedBack)}`)
      
      addResult('info', 'Step 3: Testing Buffer handling')
      const testBuffer = Buffer.from('test-kid', 'utf-8')
      addResult('info', `Buffer type: ${typeof testBuffer}, constructor: ${testBuffer.constructor.name}`)
      addResult('info', `Buffer instance check: ${testBuffer instanceof Buffer}`)
      addResult('info', `Buffer data: ${Array.from(testBuffer)}`)
      
      const testObj = {
        unprotected: {
          kid: testBuffer
        }
      }
      addResult('info', `Test object with Buffer: ${JSON.stringify(testObj, null, 2)}`)
      
      const cborTestObj = encodeMessageToCbor(testObj)
      addResult('info', `CBOR encoded test object: ${cborTestObj.toString('hex')}`)
      
      const decodedTestObj = decodeCborMessage(cborTestObj)
      addResult('info', `CBOR decoded test object: ${JSON.stringify(decodedTestObj, null, 2)}`)
      
      addResult('info', 'Step 4: Building encrypted request')
      const request = await blockstream.request(
        originalMessage,
        {
          unprotected: {
            kid: Buffer.from(kid, 'utf-8')
          }
        }
      )
      
      addResult('success', `Final encrypted request buffer length: ${request.length}`)
      addResult('info', `Final encrypted request buffer: ${request.toString('hex')}`)
      
      addResult('info', 'Step 5: Testing intermediate steps')
      const signedMessage = await signMessage(
        new Uint8Array(Buffer.from(adminPK, 'hex')), 
        cborMsg,
        {
          unprotected: {
            kid: Buffer.from(kid, 'utf-8')
          }
        }
      )
      addResult('success', `Signed message length: ${signedMessage.length}`)
      
      addResult('info', 'Step 6: Decrypting and verifying')
      const sharedKey = deriveSharedKey(new Uint8Array(Buffer.from(adminPK, 'hex')), new Uint8Array(Buffer.from(hsmPK, 'hex')))
      const decryptedRequest = await encrypt.read(
        request,
        Buffer.from(sharedKey)
      )
      
      addResult('success', `Decrypted request length: ${decryptedRequest.length}`)
      
      const adminPublicKey = p256.getPublicKey(new Uint8Array(Buffer.from(adminPK, 'hex')), true)
      const verifiedRequest = await verifyMessage(
        adminPublicKey,
        decryptedRequest
      )
      
      const finalResult = decodeCborMessage(verifiedRequest)
      addResult('success', `Verified and decoded result: ${JSON.stringify(finalResult)}`)
      
      if (JSON.stringify(finalResult) === JSON.stringify(originalMessage)) {
        addResult('success', '✅ Test PASSED: Original message matches final result!')
      } else {
        addResult('error', '❌ Test FAILED: Original message does not match final result')
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
      title="Build Request Test"
      description="Tests the complete flow of building, signing, encrypting, decrypting, and verifying a COSE request message. This simulates the Blockstream HSM communication protocol."
      onRunTest={runTest}
      results={results}
      isRunning={isRunning}
    />
  )
}

export default BuildRequestTest
