"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toSIOPRegistrationDidMethod = exports.getNetworkFromDid = exports.getMethodFromDid = exports.parseJWT = exports.getIssuerDidFromJWT = exports.isIssSelfIssued = exports.getSubDidFromPayload = exports.getAudience = exports.signRequestObjectPayload = exports.signIDTokenPayload = exports.createDidJWT = exports.verifyDidJWT = void 0;
const did_jwt_1 = require("did-jwt");
const helpers_1 = require("../helpers");
const types_1 = require("../types");
/**
 *  Verifies given JWT. If the JWT is valid, the promise returns an object including the JWT, the payload of the JWT,
 *  and the did doc of the issuer of the JWT.
 *
 *  @example
 *  verifyDidJWT('did:key:example', resolver, {audience: '5A8bRWU3F7j3REx3vkJ...', callbackUrl: 'https://...'}).then(obj => {
 *      const did = obj.did                 // DIDres of signer
 *      const payload = obj.payload
 *      const doc = obj.doc                 // DIDres Document of signer
 *      const JWT = obj.JWT                 // JWT
 *      const signerKeyId = obj.signerKeyId // ID of key in DIDres document that signed JWT
 *      ...
 *  })
 *
 *  @param    {String}            jwt                   a JSON Web Token to verify
 *  @param    {Resolvable}        resolver
 *  @param    {JWTVerifyOptions}  [options]             Options
 *  @param    {String}            options.audience      DID of the recipient of the JWT
 *  @param    {String}            options.callbackUrl   callback url in JWT
 *  @return   {Promise<Object, Error>}                  a promise which resolves with a response object or rejects with an error
 */
async function verifyDidJWT(jwt, resolver, options) {
    return (0, did_jwt_1.verifyJWT)(jwt, Object.assign(Object.assign({}, options), { resolver }));
}
exports.verifyDidJWT = verifyDidJWT;
/**
 *  Creates a signed JWT given an address which becomes the issuer, a signer function, and a payload for which the withSignature is over.
 *
 *  @example
 *  const signer = ES256KSigner(process.env.PRIVATE_KEY)
 *  createJWT({address: '5A8bRWU3F7j3REx3vkJ...', signer}, {key1: 'value', key2: ..., ... }).then(JWT => {
 *      ...
 *  })
 *
 *  @param    {Object}            payload               payload object
 *  @param    {Object}            [options]             an unsigned credential object
 *  @param    {String}            options.issuer        The DID of the issuer (signer) of JWT
 *  @param    {Signer}            options.signer        a `Signer` function, Please see `ES256KSigner` or `EdDSASigner`
 *  @param    {boolean}           options.canonicalize  optional flag to canonicalize header and payload before signing
 *  @param    {Object}            header                optional object to specify or customize the JWT header
 *  @return   {Promise<Object, Error>}                  a promise which resolves with a signed JSON Web Token or rejects with an error
 */
async function createDidJWT(payload, { issuer, signer, expiresIn, canonicalize }, header) {
    return (0, did_jwt_1.createJWT)(payload, { issuer, signer, expiresIn, canonicalize }, header);
}
exports.createDidJWT = createDidJWT;
async function signIDTokenPayload(payload, opts) {
    if (!payload.sub) {
        payload.sub = opts.signature.did;
    }
    const issuer = opts.registration.issuer || payload.iss;
    if (!issuer || !(issuer.includes(types_1.ResponseIss.SELF_ISSUED_V2) || issuer === payload.sub)) {
        throw new Error(types_1.SIOPErrors.NO_SELFISSUED_ISS);
    }
    if (!payload.iss) {
        payload.iss = issuer;
    }
    if ((0, types_1.isInternalSignature)(opts.signature)) {
        return signDidJwtInternal(payload, issuer, opts.signature.hexPrivateKey, opts.signature.alg, opts.signature.kid, opts.signature.customJwtSigner);
    }
    else if ((0, types_1.isExternalSignature)(opts.signature)) {
        return signDidJwtExternal(payload, opts.signature.signatureUri, opts.signature.authZToken, opts.signature.alg, opts.signature.kid);
    }
    else if ((0, types_1.isSuppliedSignature)(opts.signature)) {
        return signDidJwtSupplied(payload, issuer, opts.signature.signature, opts.signature.alg, opts.signature.kid);
    }
    else {
        throw new Error(types_1.SIOPErrors.BAD_SIGNATURE_PARAMS);
    }
}
exports.signIDTokenPayload = signIDTokenPayload;
async function signRequestObjectPayload(payload, opts) {
    let issuer = payload.iss;
    if (!issuer) {
        issuer = opts.signature.did;
    }
    if (!issuer) {
        throw Error('No issuer supplied to sign the JWT');
    }
    if (!payload.iss) {
        payload.iss = issuer;
    }
    if (!payload.sub) {
        payload.sub = opts.signature.did;
    }
    if ((0, types_1.isInternalSignature)(opts.signature)) {
        return signDidJwtInternal(payload, issuer, opts.signature.hexPrivateKey, opts.signature.alg, opts.signature.kid, opts.signature.customJwtSigner);
    }
    else if ((0, types_1.isExternalSignature)(opts.signature)) {
        return signDidJwtExternal(payload, opts.signature.signatureUri, opts.signature.authZToken, opts.signature.alg, opts.signature.kid);
    }
    else if ((0, types_1.isSuppliedSignature)(opts.signature)) {
        return signDidJwtSupplied(payload, issuer, opts.signature.signature, opts.signature.alg, opts.signature.kid);
    }
    else {
        throw new Error(types_1.SIOPErrors.BAD_SIGNATURE_PARAMS);
    }
}
exports.signRequestObjectPayload = signRequestObjectPayload;
async function signDidJwtInternal(payload, issuer, hexPrivateKey, alg, kid, customJwtSigner) {
    const signer = determineSigner(alg, hexPrivateKey, customJwtSigner);
    const header = {
        alg,
        kid,
    };
    const options = {
        issuer,
        signer,
        expiresIn: types_1.DEFAULT_EXPIRATION_TIME,
    };
    return await createDidJWT(Object.assign({}, payload), options, header);
}
async function signDidJwtExternal(payload, signatureUri, authZToken, alg, kid) {
    const body = {
        issuer: payload.iss && payload.iss.includes('did:') ? payload.iss : payload.sub,
        payload,
        expiresIn: types_1.DEFAULT_EXPIRATION_TIME,
        alg,
        selfIssued: payload.iss.includes(types_1.ResponseIss.SELF_ISSUED_V2) ? payload.iss : undefined,
        kid,
    };
    const response = await (0, helpers_1.post)(signatureUri, JSON.stringify(body), { bearerToken: authZToken });
    return response.successBody.jws;
}
async function signDidJwtSupplied(payload, issuer, signer, alg, kid) {
    const header = {
        alg,
        kid,
    };
    const options = {
        issuer,
        signer,
        expiresIn: types_1.DEFAULT_EXPIRATION_TIME,
    };
    return await createDidJWT(Object.assign({}, payload), options, header);
}
const determineSigner = (alg, hexPrivateKey, customSigner) => {
    if (customSigner) {
        return customSigner;
    }
    else if (!hexPrivateKey) {
        throw new Error('no private key provided');
    }
    const privateKey = (0, did_jwt_1.hexToBytes)(hexPrivateKey.replace('0x', ''));
    switch (alg) {
        case types_1.SigningAlgo.EDDSA:
            return (0, did_jwt_1.EdDSASigner)(privateKey);
        case types_1.SigningAlgo.ES256:
            return (0, did_jwt_1.ES256Signer)(privateKey);
        case types_1.SigningAlgo.ES256K:
            return (0, did_jwt_1.ES256KSigner)(privateKey);
        case types_1.SigningAlgo.PS256:
            throw Error('PS256 is not supported yet. Please provide a custom signer');
        case types_1.SigningAlgo.RS256:
            throw Error('RS256 is not supported yet. Please provide a custom signer');
    }
};
function getAudience(jwt) {
    const { payload } = (0, did_jwt_1.decodeJWT)(jwt);
    if (!payload) {
        throw new Error(types_1.SIOPErrors.NO_AUDIENCE);
    }
    else if (!payload.aud) {
        return undefined;
    }
    else if (Array.isArray(payload.aud)) {
        throw new Error(types_1.SIOPErrors.INVALID_AUDIENCE);
    }
    return payload.aud;
}
exports.getAudience = getAudience;
//TODO To enable automatic registration, it cannot be a did, but HTTPS URL
function assertIssSelfIssuedOrDid(payload) {
    if (!payload.sub || !payload.sub.startsWith('did:') || !payload.iss || !isIssSelfIssued(payload)) {
        throw new Error(types_1.SIOPErrors.NO_ISS_DID);
    }
}
function getSubDidFromPayload(payload, header) {
    assertIssSelfIssuedOrDid(payload);
    if (isIssSelfIssued(payload)) {
        let did;
        if (payload.sub && payload.sub.startsWith('did:')) {
            did = payload.sub;
        }
        if (!did && header && header.kid && header.kid.startsWith('did:')) {
            did = header.kid.split('#')[0];
        }
        if (did) {
            return did;
        }
    }
    return payload.sub;
}
exports.getSubDidFromPayload = getSubDidFromPayload;
function isIssSelfIssued(payload) {
    return payload.iss.includes(types_1.ResponseIss.SELF_ISSUED_V1) || payload.iss.includes(types_1.ResponseIss.SELF_ISSUED_V2) || payload.iss === payload.sub;
}
exports.isIssSelfIssued = isIssSelfIssued;
function getIssuerDidFromJWT(jwt) {
    const { payload } = parseJWT(jwt);
    return getSubDidFromPayload(payload);
}
exports.getIssuerDidFromJWT = getIssuerDidFromJWT;
function parseJWT(jwt) {
    const decodedJWT = (0, did_jwt_1.decodeJWT)(jwt);
    const { payload, header } = decodedJWT;
    if (!payload || !header) {
        throw new Error(types_1.SIOPErrors.NO_JWT);
    }
    return decodedJWT;
}
exports.parseJWT = parseJWT;
function getMethodFromDid(did) {
    if (!did) {
        throw new Error(types_1.SIOPErrors.BAD_PARAMS);
    }
    const split = did.split(':');
    if (split.length == 1 && did.length > 0) {
        return did;
    }
    else if (!did.startsWith('did:') || split.length < 2) {
        throw new Error(types_1.SIOPErrors.BAD_PARAMS);
    }
    return split[1];
}
exports.getMethodFromDid = getMethodFromDid;
function getNetworkFromDid(did) {
    const network = 'mainnet'; // default
    const split = did.split(':');
    if (!did.startsWith('did:') || split.length < 2) {
        throw new Error(types_1.SIOPErrors.BAD_PARAMS);
    }
    if (split.length === 4) {
        return split[2];
    }
    else if (split.length > 4) {
        return `${split[2]}:${split[3]}`;
    }
    return network;
}
exports.getNetworkFromDid = getNetworkFromDid;
/**
 * Since the OIDC SIOP spec incorrectly uses 'did:<method>:' and calls that a method, we have to fix it
 * @param didOrMethod
 */
function toSIOPRegistrationDidMethod(didOrMethod) {
    let prefix = didOrMethod;
    if (!didOrMethod.startsWith('did:')) {
        prefix = 'did:' + didOrMethod;
    }
    const split = prefix.split(':');
    return `${split[0]}:${split[1]}`;
}
exports.toSIOPRegistrationDidMethod = toSIOPRegistrationDidMethod;
