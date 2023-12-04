"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IDToken = void 0;
const Opts_1 = require("../authorization-response/Opts");
const did_1 = require("../did");
const types_1 = require("../types");
const Payload_1 = require("./Payload");
class IDToken {
    constructor(jwt, payload, responseOpts) {
        this._jwt = jwt;
        this._payload = payload;
        this._responseOpts = responseOpts;
    }
    static async fromVerifiedAuthorizationRequest(verifiedAuthorizationRequest, responseOpts, verifyOpts) {
        const authorizationRequestPayload = verifiedAuthorizationRequest.authorizationRequestPayload;
        if (!authorizationRequestPayload) {
            throw new Error(types_1.SIOPErrors.NO_REQUEST);
        }
        const idToken = new IDToken(null, await (0, Payload_1.createIDTokenPayload)(verifiedAuthorizationRequest, responseOpts), responseOpts);
        if (verifyOpts) {
            await idToken.verify(verifyOpts);
        }
        return idToken;
    }
    static async fromIDToken(idTokenJwt, verifyOpts) {
        if (!idTokenJwt) {
            throw new Error(types_1.SIOPErrors.NO_JWT);
        }
        const idToken = new IDToken(idTokenJwt, undefined);
        if (verifyOpts) {
            await idToken.verify(verifyOpts);
        }
        return idToken;
    }
    static async fromIDTokenPayload(idTokenPayload, responseOpts, verifyOpts) {
        if (!idTokenPayload) {
            throw new Error(types_1.SIOPErrors.NO_JWT);
        }
        const idToken = new IDToken(null, idTokenPayload, responseOpts);
        if (verifyOpts) {
            await idToken.verify(verifyOpts);
        }
        return idToken;
    }
    async payload() {
        if (!this._payload) {
            if (!this._jwt) {
                throw new Error(types_1.SIOPErrors.NO_JWT);
            }
            const { header, payload } = this.parseAndVerifyJwt();
            this._header = header;
            this._payload = payload;
        }
        return this._payload;
    }
    async jwt() {
        if (!this._jwt) {
            if (!this.responseOpts) {
                throw Error(types_1.SIOPErrors.BAD_SIGNATURE_PARAMS);
            }
            this._jwt = await (0, did_1.signIDTokenPayload)(this._payload, this.responseOpts);
            const { header, payload } = this.parseAndVerifyJwt();
            this._header = header;
            this._payload = payload;
        }
        return this._jwt;
    }
    parseAndVerifyJwt() {
        const { header, payload } = (0, did_1.parseJWT)(this._jwt);
        this.assertValidResponseJWT({ header, payload });
        const idTokenPayload = payload;
        return { header, payload: idTokenPayload };
    }
    /**
     * Verifies a SIOP ID Response JWT on the RP Side
     *
     * @param idToken ID token to be validated
     * @param verifyOpts
     */
    async verify(verifyOpts) {
        var _a, _b, _c, _d;
        (0, Opts_1.assertValidVerifyOpts)(verifyOpts);
        const { header, payload } = (0, did_1.parseJWT)(await this.jwt());
        this.assertValidResponseJWT({ header, payload });
        const verifiedJWT = await (0, did_1.verifyDidJWT)(await this.jwt(), (0, did_1.getResolver)(verifyOpts.verification.resolveOpts), Object.assign(Object.assign({}, (_a = verifyOpts.verification.resolveOpts) === null || _a === void 0 ? void 0 : _a.jwtVerifyOpts), { audience: (_b = verifyOpts.audience) !== null && _b !== void 0 ? _b : (_d = (_c = verifyOpts.verification.resolveOpts) === null || _c === void 0 ? void 0 : _c.jwtVerifyOpts) === null || _d === void 0 ? void 0 : _d.audience }));
        const issuerDid = (0, did_1.getSubDidFromPayload)(payload);
        if (verifyOpts.verification.checkLinkedDomain && verifyOpts.verification.checkLinkedDomain !== types_1.CheckLinkedDomain.NEVER) {
            await (0, did_1.validateLinkedDomainWithDid)(issuerDid, verifyOpts.verification);
        }
        else if (!verifyOpts.verification.checkLinkedDomain) {
            await (0, did_1.validateLinkedDomainWithDid)(issuerDid, verifyOpts.verification);
        }
        const verPayload = verifiedJWT.payload;
        this.assertValidResponseJWT({ header, verPayload: verPayload, audience: verifyOpts.audience });
        // Enforces verifyPresentationCallback function on the RP side,
        if (!(verifyOpts === null || verifyOpts === void 0 ? void 0 : verifyOpts.verification.presentationVerificationCallback)) {
            throw new Error(types_1.SIOPErrors.VERIFIABLE_PRESENTATION_VERIFICATION_FUNCTION_MISSING);
        }
        return {
            jwt: await this.jwt(),
            didResolutionResult: verifiedJWT.didResolutionResult,
            signer: verifiedJWT.signer,
            issuer: issuerDid,
            payload: Object.assign({}, verPayload),
            verifyOpts,
        };
    }
    static async verify(idTokenJwt, verifyOpts) {
        const idToken = await IDToken.fromIDToken(idTokenJwt, verifyOpts);
        const verifiedIdToken = await idToken.verify(verifyOpts);
        return Object.assign({}, verifiedIdToken);
    }
    assertValidResponseJWT(opts) {
        if (!opts.header) {
            throw new Error(types_1.SIOPErrors.BAD_PARAMS);
        }
        if (opts.payload) {
            if (!opts.payload.iss || !(opts.payload.iss.includes(types_1.ResponseIss.SELF_ISSUED_V2) || opts.payload.iss.startsWith('did:'))) {
                throw new Error(`${types_1.SIOPErrors.NO_SELFISSUED_ISS}, got: ${opts.payload.iss}`);
            }
        }
        if (opts.verPayload) {
            if (!opts.verPayload.nonce) {
                throw Error(types_1.SIOPErrors.NO_NONCE);
                // No need for our own expiration check. DID jwt already does that
                /*} else if (!opts.verPayload.exp || opts.verPayload.exp < Date.now() / 1000) {
                throw Error(SIOPErrors.EXPIRED);
                /!*} else if (!opts.verPayload.iat || opts.verPayload.iat > (Date.now() / 1000)) {
                                  throw Error(SIOPErrors.EXPIRED);*!/
                // todo: Add iat check
        
               */
            }
            if ((opts.verPayload.aud && !opts.audience) || (!opts.verPayload.aud && opts.audience)) {
                throw Error(types_1.SIOPErrors.NO_AUDIENCE);
            }
            else if (opts.audience && opts.audience != opts.verPayload.aud) {
                throw Error(types_1.SIOPErrors.INVALID_AUDIENCE);
            }
            else if (opts.nonce && opts.nonce != opts.verPayload.nonce) {
                throw Error(types_1.SIOPErrors.BAD_NONCE);
            }
        }
    }
    get header() {
        return this._header;
    }
    get responseOpts() {
        return this._responseOpts;
    }
    async isSelfIssued() {
        const payload = await this.payload();
        return payload.iss === types_1.ResponseIss.SELF_ISSUED_V2 || (payload.sub !== undefined && payload.sub === payload.iss);
    }
}
exports.IDToken = IDToken;
