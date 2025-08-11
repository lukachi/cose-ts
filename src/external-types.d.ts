// Type declarations for packages without TypeScript definitions

declare module 'aes-cbc-mac' {
  export function create(key: Buffer, data: Buffer, length: number): Buffer;
}

declare module 'node-hkdf-sync' {
  export default class HKDF {
    constructor(algorithm: string, salt: Buffer | undefined, ikm: Buffer);
    derive(info: Buffer, length: number): Buffer;
  }
}

declare module 'node-rsa' {
  export default class NodeRSA {
    importKey(key: any, format: string): this;
    setOptions(options: any): void;
    sign(data: Buffer): Buffer;
    verify(data: Buffer, signature: Buffer, source?: string, encoding?: string): boolean;
  }
}

declare module 'elliptic' {
  export class ec {
    constructor(curve: string);
    keyFromPrivate(key: Buffer): any;
    keyFromPublic(key: any): any;
    curve: any;
  }
}
