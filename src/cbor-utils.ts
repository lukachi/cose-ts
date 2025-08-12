// Browser-compatible CBOR utilities

let cborLib: any;
let isNode = false;
let isBrowser = false;

// Detect environment
if (typeof window !== 'undefined') {
    isBrowser = true;
} else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    isNode = true;
}

// Try to import the best available CBOR library
try {
    if (isBrowser) {
        try {
            cborLib = require('cbor2');
        } catch (e) {
            try {
                cborLib = require('cbor');
            } catch (e2) {
                console.warn('No CBOR library found for browser environment');
            }
        }
    } else {
        try {
            cborLib = require('cbor');
        } catch (e) {
            try {
                cborLib = require('cbor2');
            } catch (e2) {
                console.warn('No CBOR library found for Node.js environment');
            }
        }
    }
} catch (e) {
    console.error('Failed to load CBOR library:', e);
}

// Unified byte-like structure detection and conversion
const isByteStructure = (data: any): boolean => {
    return data instanceof Uint8Array ||
           (typeof Buffer !== 'undefined' && data instanceof Buffer) ||
           (data && typeof data === 'object' && data.type === 'Buffer' && Array.isArray(data.data));
};

const toUint8Array = (data: any): Uint8Array => {
    if (data instanceof Uint8Array) {
        return data;
    }
    if (typeof Buffer !== 'undefined' && data instanceof Buffer) {
        return new Uint8Array(data);
    }
    if (data && typeof data === 'object' && data.type === 'Buffer' && Array.isArray(data.data)) {
        return new Uint8Array(data.data);
    }
    throw new Error('Cannot convert to Uint8Array');
};

// Simplified preprocessing
const preprocessData = (data: any): any => {
    if (data === null || data === undefined) {
        return data;
    }
    
    // Convert any byte-like structure to Uint8Array
    if (isByteStructure(data)) {
        return toUint8Array(data);
    }
    
    // Handle arrays
    if (Array.isArray(data)) {
        return data.map(preprocessData);
    }
    
    // Handle Maps
    if (data instanceof Map) {
        const newMap = new Map();
        for (const [key, value] of data.entries()) {
            newMap.set(preprocessData(key), preprocessData(value));
        }
        return newMap;
    }
    
    // Handle plain objects
    if (typeof data === 'object' && data.constructor === Object) {
        const newObj: any = {};
        for (const [key, value] of Object.entries(data)) {
            newObj[key] = preprocessData(value);
        }
        return newObj;
    }
    
    return data;
};

export const encode = (data: any): Uint8Array => {
    if (!cborLib) {
        throw new Error('No CBOR library available');
    }
    
    const processedData = preprocessData(data);
    
    try {
        const result = cborLib.encode(processedData);
        
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
        
        throw new Error('Unexpected CBOR encode result type: ' + typeof result);
    } catch (e) {
        console.error('CBOR encode failed:', e);
        throw e;
    }
};

export const decode = <T = any>(data: Uint8Array | Buffer | ArrayBuffer | number[]): T => {
    if (!cborLib) {
        throw new Error('No CBOR library available');
    }
    
    // Convert input to Uint8Array
    let input: Uint8Array;
    if (data instanceof Uint8Array) {
        input = data;
    } else if (typeof Buffer !== 'undefined' && data instanceof Buffer) {
        input = new Uint8Array(data);
    } else if (data instanceof ArrayBuffer) {
        input = new Uint8Array(data);
    } else if (Array.isArray(data)) {
        input = new Uint8Array(data);
    } else {
        throw new Error('Invalid input data type for CBOR decode');
    }
    
    try {
        return cborLib.decode(input);
    } catch (e) {
        console.error('CBOR decode failed:', e);
        throw e;
    }
};

// Tagged value helper
export const createTag = (tag: number, value: any) => {
    const preparedValue = preprocessData(value);
    
    if (cborLib.Tagged) {
        return new cborLib.Tagged(tag, preparedValue);
    }
    if (cborLib.Tag) {
        return new cborLib.Tag(tag, preparedValue);
    }
    
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
