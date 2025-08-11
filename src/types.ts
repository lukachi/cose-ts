/**
 * COSE TypeScript type definitions
 */

export interface AlgToTagsMap {
  [key: string]: number;
}

export interface HeaderParametersMap {
  [key: string]: number;
}

export interface KeyParametersMap {
  [key: string]: number;
}

export interface KeyTypesMap {
  [key: string]: number;
}

export interface KeyCrvMap {
  [key: string]: number;
}

export interface COSEHeaders {
  p?: { [key: string]: any };
  u?: { [key: string]: any };
}

export interface COSEKey {
  kty?: string;
  crv?: string;
  x?: Buffer;
  y?: Buffer;
  d?: Buffer;
  k?: Buffer;
  kid?: string;
  [key: string]: any;
}

export interface COSERecipient {
  key: COSEKey | Buffer;
  p?: { [key: string]: any };
  u?: { [key: string]: any };
  sender?: COSEKey;
  externalAAD?: Buffer;
}

export interface COSESigner {
  key: COSEKey;
  p?: { [key: string]: any };
  u?: { [key: string]: any };
  externalAAD?: Buffer;
}

export interface COSEVerifier {
  key: COSEKey;
  externalAAD?: Buffer;
}

export interface COSEOptions {
  externalAAD?: Buffer;
  randomSource?: (bytes: number) => Buffer;
  contextIv?: Buffer;
  excludetag?: boolean;
  encodep?: string;
  defaultType?: number;
}

export interface NodeAlgorithm {
  sign?: string;
  digest?: string;
  alg?: string;
  saltLen?: number;
}

export interface AlgorithmInfo {
  sign: string;
  digest: string;
}

export type RandomSourceFunction = (bytes: number) => Buffer;
