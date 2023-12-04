"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.calculateJwkThumbprintUri = exports.isEd25519DidKeyMethod = void 0;
// import { keyUtils as ed25519KeyUtils } from '@transmute/did-key-ed25519';
// import { ec as EC } from 'elliptic';
const u8a = __importStar(require("uint8arrays"));
const ED25519_DID_KEY = 'did:key:z6Mk';
const isEd25519DidKeyMethod = (did) => {
    return did && did.includes(ED25519_DID_KEY);
};
exports.isEd25519DidKeyMethod = isEd25519DidKeyMethod;
/*
export const isEd25519JWK = (jwk: JWK): boolean => {
  return jwk && !!jwk.crv && jwk.crv === KeyCurve.ED25519;
};

export const getBase58PrivateKeyFromHexPrivateKey = (hexPrivateKey: string): string => {
  return bs58.encode(Buffer.from(hexPrivateKey, 'hex'));
};

export const getPublicED25519JWKFromHexPrivateKey = (hexPrivateKey: string, kid?: string): JWK => {
  const ec = new EC('ed25519');
  const privKey = ec.keyFromPrivate(hexPrivateKey);
  const pubPoint = privKey.getPublic();

  return toJWK(kid, KeyCurve.ED25519, pubPoint);
};

const getPublicSECP256k1JWKFromHexPrivateKey = (hexPrivateKey: string, kid: string) => {
  const ec = new EC('secp256k1');
  const privKey = ec.keyFromPrivate(hexPrivateKey.replace('0x', ''), 'hex');
  const pubPoint = privKey.getPublic();
  return toJWK(kid, KeyCurve.SECP256k1, pubPoint);
};

export const getPublicJWKFromHexPrivateKey = (hexPrivateKey: string, kid?: string, did?: string): JWK => {
  if (isEd25519DidKeyMethod(did)) {
    return getPublicED25519JWKFromHexPrivateKey(hexPrivateKey, kid);
  }
  return getPublicSECP256k1JWKFromHexPrivateKey(hexPrivateKey, kid);
};

const toJWK = (kid: string, crv: KeyCurve, pubPoint: EC.BN) => {
  return {
    kid,
    kty: KeyType.EC,
    crv: crv,
    x: base64url.toBase64(pubPoint.getX().toArrayLike(Buffer)),
    y: base64url.toBase64(pubPoint.getY().toArrayLike(Buffer))
  };
};

// from fingerprintFromPublicKey function in @transmute/Ed25519KeyPair
const getThumbprintFromJwkDIDKeyImpl = (jwk: JWK): string => {
  // ed25519 cryptonyms are multicodec encoded values, specifically:
  // (multicodec ed25519-pub 0xed01 + key bytes)
  const pubkeyBytes = base64url.toBuffer(jwk.x);
  const buffer = new Uint8Array(2 + pubkeyBytes.length);
  buffer[0] = 0xed;
  buffer[1] = 0x01;
  buffer.set(pubkeyBytes, 2);

  // prefix with `z` to indicate multi-base encodingFormat

  return base64url.encode(`z${u8a.toString(buffer, 'base58btc')}`);
};

export const getThumbprintFromJwk = async (jwk: JWK, did: string): Promise<string> => {
  if (isEd25519DidKeyMethod(did)) {
    return getThumbprintFromJwkDIDKeyImpl(jwk);
  } else {
    return await calculateJwkThumbprint(jwk, 'sha256');
  }
};

export const getThumbprint = async (hexPrivateKey: string, did: string): Promise<string> => {
  return await getThumbprintFromJwk(
    isEd25519DidKeyMethod(did) ? getPublicED25519JWKFromHexPrivateKey(hexPrivateKey) : getPublicJWKFromHexPrivateKey(hexPrivateKey),
    did
  );
};
*/
const check = (value, description) => {
    if (typeof value !== 'string' || !value) {
        throw Error(`${description} missing or invalid`);
    }
};
async function calculateJwkThumbprint(jwk, digestAlgorithm) {
    if (!jwk || typeof jwk !== 'object') {
        throw new TypeError('JWK must be an object');
    }
    const algorithm = digestAlgorithm !== null && digestAlgorithm !== void 0 ? digestAlgorithm : 'sha256';
    if (algorithm !== 'sha256' && algorithm !== 'sha384' && algorithm !== 'sha512') {
        throw new TypeError('digestAlgorithm must one of "sha256", "sha384", or "sha512"');
    }
    let components;
    switch (jwk.kty) {
        case 'EC':
            check(jwk.crv, '"crv" (Curve) Parameter');
            check(jwk.x, '"x" (X Coordinate) Parameter');
            check(jwk.y, '"y" (Y Coordinate) Parameter');
            components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
            break;
        case 'OKP':
            check(jwk.crv, '"crv" (Subtype of Key Pair) Parameter');
            check(jwk.x, '"x" (Public Key) Parameter');
            components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
            break;
        case 'RSA':
            check(jwk.e, '"e" (Exponent) Parameter');
            check(jwk.n, '"n" (Modulus) Parameter');
            components = { e: jwk.e, kty: jwk.kty, n: jwk.n };
            break;
        case 'oct':
            check(jwk.k, '"k" (Key Value) Parameter');
            components = { k: jwk.k, kty: jwk.kty };
            break;
        default:
            throw Error('"kty" (Key Type) Parameter missing or unsupported');
    }
    const data = u8a.fromString(JSON.stringify(components), 'utf-8');
    return u8a.toString(await digest(algorithm, data), 'base64url');
}
const digest = async (algorithm, data) => {
    const subtleDigest = `SHA-${algorithm.slice(-3)}`;
    return new Uint8Array(await crypto.subtle.digest(subtleDigest, data));
};
async function calculateJwkThumbprintUri(jwk, digestAlgorithm) {
    digestAlgorithm !== null && digestAlgorithm !== void 0 ? digestAlgorithm : (digestAlgorithm = 'sha256');
    const thumbprint = await calculateJwkThumbprint(jwk, digestAlgorithm);
    return `urn:ietf:params:oauth:jwk-thumbprint:sha-${digestAlgorithm.slice(-3)}:${thumbprint}`;
}
exports.calculateJwkThumbprintUri = calculateJwkThumbprintUri;
