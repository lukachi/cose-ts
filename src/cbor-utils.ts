// Browser-compatible CBOR utilities

let cborLib: any;
let isNode = false;
let isBrowser = false;

// Detect environment
if (typeof window !== 'undefined') {
    isBrowser = true;
    console.log('Detected browser environment');
} else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    isNode = true;
    console.log('Detected Node.js environment');
}

// Try to import the best available CBOR library
try {
    if (isBrowser) {
        // For browser, prefer cbor2 or cbor
        try {
            cborLib = require('cbor2');
            console.log('Using cbor2 in browser');
        } catch (e) {
            try {
                cborLib = require('cbor');
                console.log('Using cbor in browser');
            } catch (e2) {
                console.warn('No CBOR library found for browser environment');
            }
        }
    } else {
        // For Node.js, use cbor
        try {
            cborLib = require('cbor');
            console.log('Using cbor in Node.js');
        } catch (e) {
            try {
                cborLib = require('cbor2');
                console.log('Using cbor2 in Node.js');
            } catch (e2) {
                console.warn('No CBOR library found for Node.js environment');
            }
        }
    }
} catch (e) {
    console.error('Failed to load CBOR library:', e);
}

// Helper to convert Buffer-like objects to Uint8Array in browser
const prepareForEncoding = (data: any): any => {
    console.log('Preparing for encoding:', typeof data, data?.constructor?.name);
    
    if (typeof data === 'object' && data !== null) {
        // Handle Buffer objects that got serialized incorrectly
        if (data.type === 'Buffer' && Array.isArray(data.data)) {
            console.log('Found serialized Buffer, converting to Uint8Array');
            return new Uint8Array(data.data);
        }
        
        // Handle Buffer instances (this handles both Buffer and Uint8Array)
        if (data instanceof Uint8Array || (typeof Buffer !== 'undefined' && data instanceof Buffer)) {
            console.log('Found Buffer/Uint8Array, ensuring it stays as Uint8Array');
            return new Uint8Array(data);
        }
        
        // Handle arrays recursively
        if (Array.isArray(data)) {
            console.log('Processing array recursively');
            return data.map(prepareForEncoding);
        }
        
        // Handle objects recursively
        if (data.constructor === Object) {
            console.log('Processing object recursively');
            const result: any = {};
            for (const [key, value] of Object.entries(data)) {
                result[key] = prepareForEncoding(value);
            }
            return result;
        }
        
        // Handle Maps
        if (data instanceof Map) {
            console.log('Processing Map recursively');
            const result = new Map();
            for (const [key, value] of data.entries()) {
                result.set(key, prepareForEncoding(value));
            }
            return result;
        }
    }
    
    return data;
};

export const encode = (data: any): Uint8Array => {
    if (!cborLib) {
        throw new Error('No CBOR library available');
    }
    
    console.log('*** CBOR ENCODE FUNCTION v3.0 - FORCE REFRESH ***');
    console.log('Encoding with CBOR library:', cborLib.constructor?.name || 'unknown');
    console.log('Input data raw:', data);
    
    // Deep clone and convert all Buffers to proper byte arrays
    const convertBuffersToBytes = (obj: any): any => {
        if (obj === null || obj === undefined) {
            return obj;
        }
        
        // Handle Buffer objects (both actual Buffers and serialized ones)
        if (obj instanceof Uint8Array || (typeof Buffer !== 'undefined' && obj instanceof Buffer)) {
            console.log('Converting Buffer/Uint8Array to byte array:', Array.from(obj));
            return new Uint8Array(obj);
        }
        
        // Handle serialized Buffer objects {type: "Buffer", data: [...]}
        if (typeof obj === 'object' && obj.type === 'Buffer' && Array.isArray(obj.data)) {
            console.log('Converting serialized Buffer to byte array:', obj.data);
            return new Uint8Array(obj.data);
        }
        
        // Handle arrays
        if (Array.isArray(obj)) {
            return obj.map(convertBuffersToBytes);
        }
        
        // Handle Maps
        if (obj instanceof Map) {
            const newMap = new Map();
            for (const [key, value] of obj.entries()) {
                newMap.set(convertBuffersToBytes(key), convertBuffersToBytes(value));
            }
            return newMap;
        }
        
        // Handle plain objects
        if (typeof obj === 'object' && obj.constructor === Object) {
            const newObj: any = {};
            for (const [key, value] of Object.entries(obj)) {
                newObj[key] = convertBuffersToBytes(value);
            }
            return newObj;
        }
        
        return obj;
    };
    
    const processedData = convertBuffersToBytes(data);
    console.log('Processed data:', processedData);
    
    let result: any;
    
    try {
        // Different libraries have different APIs
        if (cborLib.encode) {
            result = cborLib.encode(processedData);
        } else {
            throw new Error('CBOR library does not have encode method');
        }
    } catch (e) {
        console.error('CBOR encode failed:', e);
        throw e;
    }
    
    console.log('Encode result type:', typeof result);
    console.log('Encode result constructor:', result?.constructor?.name);
    console.log('Encode result length:', result?.length);
    console.log('Encode result (first 20 bytes):', result instanceof Uint8Array ? Array.from(result.slice(0, 20)) : result);
    
    // Ensure we always return Uint8Array
    if (result instanceof Uint8Array) {
        return result;
    }
    
    if (result instanceof ArrayBuffer) {
        return new Uint8Array(result);
    }
    
    if (typeof Buffer !== 'undefined' && result instanceof Buffer) {
        return new Uint8Array(result);
    }
    
    if (Array.isArray(result)) {
        return new Uint8Array(result);
    }
    
    if (typeof result === 'string') {
        // Assume hex string
        const bytes = [];
        for (let i = 0; i < result.length; i += 2) {
            bytes.push(parseInt(result.substr(i, 2), 16));
        }
        return new Uint8Array(bytes);
    }
    
    // Fallback: try to convert to bytes
    if (result && typeof result === 'object') {
        try {
            return new Uint8Array(Object.values(result));
        } catch (e) {
            console.error('Failed to convert result to Uint8Array:', e);
            throw new Error('Cannot convert CBOR encode result to Uint8Array');
        }
    }
    
    throw new Error('Unexpected CBOR encode result type: ' + typeof result);
};

export const decode = <T = any>(data: Uint8Array | Buffer | ArrayBuffer | number[]): T => {
    if (!cborLib) {
        throw new Error('No CBOR library available');
    }
    
    console.log('Decoding with CBOR library:', cborLib.constructor?.name || 'unknown');
    console.log('Input data type:', typeof data);
    console.log('Input data constructor:', data?.constructor?.name);
    console.log('Input data length:', (data as any)?.length || (data instanceof ArrayBuffer ? data.byteLength : 'unknown'));
    
    // Convert to format the library expects
    let input: any = data;
    
    if (data instanceof Buffer) {
        input = new Uint8Array(data);
    } else if (data instanceof ArrayBuffer) {
        input = new Uint8Array(data);
    } else if (Array.isArray(data)) {
        input = new Uint8Array(data);
    }
    
    console.log('Converted input type:', typeof input);
    console.log('Converted input constructor:', input?.constructor?.name);
    
    try {
        let result: T;
        
        if (cborLib.decode) {
            result = cborLib.decode(input);
        } else {
            throw new Error('CBOR library does not have decode method');
        }
        
        console.log('Decode result:', result);
        return result;
    } catch (e) {
        console.error('CBOR decode failed:', e);
        throw e;
    }
};

// Tagged value helper
export const createTag = (tag: number, value: any) => {
    console.log('Creating tag:', tag, 'with value:', value);
    
    // Prepare value for proper encoding
    const preparedValue = prepareForEncoding(value);
    console.log('Prepared value for tag:', preparedValue);
    
    if (cborLib.Tagged) {
        return new cborLib.Tagged(tag, preparedValue);
    }
    
    if (cborLib.Tag) {
        return new cborLib.Tag(tag, preparedValue);
    }
    
    // Fallback for libraries without Tag support
    console.warn('CBOR library does not support Tagged values, using fallback');
    return { tag, value: preparedValue };
};

export const isTagged = (obj: any): boolean => {
    if (!obj) return false;
    
    if (cborLib.Tagged && obj instanceof cborLib.Tagged) {
        return true;
    }
    
    if (cborLib.Tag && obj instanceof cborLib.Tag) {
        return true;
    }
    
    // Fallback check
    return typeof obj === 'object' && 'tag' in obj && 'value' in obj;
};

export const getTagNumber = (obj: any): number => {
    if (cborLib.Tagged && obj instanceof cborLib.Tagged) {
        return obj.tag;
    }
    
    if (cborLib.Tag && obj instanceof cborLib.Tag) {
        return obj.tag;
    }
    
    return obj.tag;
};

export const getTagValue = (obj: any): any => {
    if (cborLib.Tagged && obj instanceof cborLib.Tagged) {
        return obj.value;
    }
    
    if (cborLib.Tag && obj instanceof cborLib.Tag) {
        return obj.contents || obj.value;
    }
    
    return obj.value;
};

// Environment info
export const getEnvironmentInfo = () => {
    return {
        isNode,
        isBrowser,
        hasBuffer: typeof Buffer !== 'undefined',
        hasWindow: typeof window !== 'undefined',
        hasProcess: typeof process !== 'undefined',
        cborLibrary: cborLib?.constructor?.name || 'unknown'
    };
};
