import { Buffer } from 'buffer';
import * as cbor2 from 'cbor2';

// Browser-compatible CBOR utilities using cbor2 exclusively
let isNode = false;
let isBrowser = false;

// Detect environment
if (typeof window !== 'undefined') {
    isBrowser = true;
} else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    isNode = true;
}

// Helper to convert Buffer-like objects to Uint8Array in browser
const prepareForEncoding = (data: any): any => {
    
    if (typeof data === 'object' && data !== null) {
        // Handle Buffer objects that got serialized incorrectly
        if (data.type === 'Buffer' && Array.isArray(data.data)) {
            return new Uint8Array(data.data);
        }
        
        // Handle Buffer instances (this handles both Buffer and Uint8Array)
        if (data instanceof Uint8Array || (typeof Buffer !== 'undefined' && data instanceof Buffer)) {
            return new Uint8Array(data);
        }
        
        // Handle arrays recursively
        if (Array.isArray(data)) {
            return data.map(prepareForEncoding);
        }
        
        // Handle objects recursively
        if (data.constructor === Object) {
            const result: any = {};
            for (const [key, value] of Object.entries(data)) {
                result[key] = prepareForEncoding(value);
            }
            return result;
        }
        
        // Handle Maps
        if (data instanceof Map) {
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
    
    // Deep clone and convert all Buffers to proper byte arrays for cbor2
    const convertBuffersToBytes = (obj: any): any => {
        if (obj === null || obj === undefined) {
            return obj;
        }
        
        // Handle Buffer objects (both actual Buffers and serialized ones)
        if (obj instanceof Uint8Array || (typeof Buffer !== 'undefined' && obj instanceof Buffer)) {
            return new Uint8Array(obj);
        }
        
        // Handle serialized Buffer objects {type: "Buffer", data: [...]}
        if (typeof obj === 'object' && obj.type === 'Buffer' && Array.isArray(obj.data)) {
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
    
    try {
        // cbor2 uses encode method
        const result = cbor2.encode(processedData) as any;
        
        // cbor2 returns Uint8Array, ensure we always return Uint8Array
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
        
        throw new Error('Unexpected cbor2 encode result type: ' + typeof result);
    } catch (e) {
        console.error('cbor2 encode failed:', e);
        throw e;
    }
};

export const decode = <T = any>(data: Uint8Array | Buffer | ArrayBuffer | number[] | any): T => {
    
    // Convert input to Uint8Array format that cbor2 expects
    let input: Uint8Array;
    
    // Handle different input types more robustly
    if (data instanceof Uint8Array) {
        input = data;
    } else if (typeof Buffer !== 'undefined' && data instanceof Buffer) {
        input = new Uint8Array(data);
    } else if (data instanceof ArrayBuffer) {
        input = new Uint8Array(data);
    } else if (Array.isArray(data)) {
        input = new Uint8Array(data);
    } else if (data && typeof data === 'object' && 'data' in data && Array.isArray((data as any).data)) {
        // Handle serialized Buffer objects {type: "Buffer", data: [...]}
        input = new Uint8Array((data as any).data);
    } else if (data && typeof data === 'object' && typeof (data as any).length === 'number') {
        // Handle array-like objects
        const arrayData = Array.from(data as any).filter((item: any) => typeof item === 'number');
        input = new Uint8Array(arrayData);
    } else {
        throw new Error('Unsupported input type for cbor2 decode: ' + typeof data + ', constructor: ' + ((data as any)?.constructor?.name || 'unknown'));
    }
    
    try {
        // cbor2 uses decode method
        const result: T = cbor2.decode(input);
        return result;
    } catch (e) {
        console.error('cbor2 decode failed:', e);
        throw e;
    }
};

// Tagged value helper
export const createTag = (tag: number, value: any) => {
    
    // Prepare value for proper encoding
    const preparedValue = prepareForEncoding(value);
    
    // cbor2 uses Tag class (not Tagged)
    if (cbor2.Tag) {
        return new cbor2.Tag(tag, preparedValue);
    }
    
    // Fallback for unexpected cases
    throw new Error('cbor2 Tag class is not available');
};

export const isTagged = (obj: any): boolean => {
    if (!obj) return false;
    
    
    // cbor2 uses Tag class (not Tagged)
    if (cbor2.Tag && obj instanceof cbor2.Tag) {
        return true;
    }
    
    // Fallback check for plain objects with tag/value or tag/contents structure
    return typeof obj === 'object' && 'tag' in obj && ('value' in obj || 'contents' in obj);
};

export const getTagNumber = (obj: any): number => {
    
    // cbor2 uses Tag class (not Tagged)
    if (cbor2.Tag && obj instanceof cbor2.Tag) {
        return obj.tag as number;
    }
    
    // Fallback for plain objects
    if (typeof obj === 'object' && 'tag' in obj) {
        return obj.tag;
    }
    
    throw new Error('Object is not a valid tagged value');
};

export const getTagValue = (obj: any): any => {
    
    // cbor2 uses Tag class with 'contents' property (not 'value')
    if (cbor2.Tag && obj instanceof cbor2.Tag) {
        return obj.contents;
    }
    
    // Fallback for plain objects - check both 'value' and 'contents'
    if (typeof obj === 'object') {
        if ('contents' in obj) {
            return obj.contents;
        }
        if ('value' in obj) {
            return obj.value;
        }
    }
    
    throw new Error('Object is not a valid tagged value');
};

// Environment info
export const getEnvironmentInfo = () => {
    return {
        isNode,
        isBrowser,
        hasBuffer: typeof Buffer !== 'undefined',
        hasWindow: typeof window !== 'undefined',
        hasProcess: typeof process !== 'undefined',
        cborLibrary: 'cbor2'
    };
};
