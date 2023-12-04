"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthorizationResponse = void 0;
const authorization_request_1 = require("../authorization-request");
const Opts_1 = require("../authorization-request/Opts");
const id_token_1 = require("../id-token");
const types_1 = require("../types");
const OpenID4VP_1 = require("./OpenID4VP");
const Opts_2 = require("./Opts");
const Payload_1 = require("./Payload");
class AuthorizationResponse {
    constructor({ authorizationResponsePayload, idToken, responseOpts, authorizationRequest, }) {
        this._authorizationRequest = authorizationRequest;
        this._options = responseOpts;
        this._idToken = idToken;
        this._payload = authorizationResponsePayload;
    }
    /**
     * Creates a SIOP Response Object
     *
     * @param requestObject
     * @param responseOpts
     * @param verifyOpts
     */
    static async fromRequestObject(requestObject, responseOpts, verifyOpts) {
        (0, Opts_1.assertValidVerifyAuthorizationRequestOpts)(verifyOpts);
        (0, Opts_2.assertValidResponseOpts)(responseOpts);
        if (!requestObject || !requestObject.startsWith('ey')) {
            throw new Error(types_1.SIOPErrors.NO_JWT);
        }
        const authorizationRequest = await authorization_request_1.AuthorizationRequest.fromUriOrJwt(requestObject);
        return AuthorizationResponse.fromAuthorizationRequest(authorizationRequest, responseOpts, verifyOpts);
    }
    static async fromPayload(authorizationResponsePayload, responseOpts) {
        if (!authorizationResponsePayload) {
            throw new Error(types_1.SIOPErrors.NO_RESPONSE);
        }
        if (responseOpts) {
            (0, Opts_2.assertValidResponseOpts)(responseOpts);
        }
        const idToken = await id_token_1.IDToken.fromIDToken(authorizationResponsePayload.id_token);
        return new AuthorizationResponse({ authorizationResponsePayload, idToken, responseOpts });
    }
    static async fromAuthorizationRequest(authorizationRequest, responseOpts, verifyOpts) {
        (0, Opts_2.assertValidResponseOpts)(responseOpts);
        if (!authorizationRequest) {
            throw new Error(types_1.SIOPErrors.NO_REQUEST);
        }
        const verifiedRequest = await authorizationRequest.verify(verifyOpts);
        return await AuthorizationResponse.fromVerifiedAuthorizationRequest(verifiedRequest, responseOpts, verifyOpts);
    }
    static async fromVerifiedAuthorizationRequest(verifiedAuthorizationRequest, responseOpts, verifyOpts) {
        (0, Opts_2.assertValidResponseOpts)(responseOpts);
        if (!verifiedAuthorizationRequest) {
            throw new Error(types_1.SIOPErrors.NO_REQUEST);
        }
        const authorizationRequest = verifiedAuthorizationRequest.authorizationRequest;
        // const merged = verifiedAuthorizationRequest.authorizationRequest.requestObject, verifiedAuthorizationRequest.requestObject);
        // const presentationDefinitions = await PresentationExchange.findValidPresentationDefinitions(merged, await authorizationRequest.getSupportedVersion());
        const presentationDefinitions = JSON.parse(JSON.stringify(verifiedAuthorizationRequest.presentationDefinitions));
        const wantsIdToken = await authorizationRequest.containsResponseType(types_1.ResponseType.ID_TOKEN);
        // const hasVpToken = await authorizationRequest.containsResponseType(ResponseType.VP_TOKEN);
        const idToken = wantsIdToken ? await id_token_1.IDToken.fromVerifiedAuthorizationRequest(verifiedAuthorizationRequest, responseOpts) : undefined;
        const idTokenPayload = wantsIdToken ? await idToken.payload() : undefined;
        const authorizationResponsePayload = await (0, Payload_1.createResponsePayload)(authorizationRequest, responseOpts, idTokenPayload);
        const response = new AuthorizationResponse({
            authorizationResponsePayload,
            idToken,
            responseOpts,
            authorizationRequest,
        });
        const wrappedPresentations = await (0, OpenID4VP_1.extractPresentationsFromAuthorizationResponse)(response);
        await (0, OpenID4VP_1.assertValidVerifiablePresentations)({
            presentationDefinitions,
            presentations: wrappedPresentations,
            verificationCallback: verifyOpts.verification.presentationVerificationCallback,
            opts: Object.assign({}, responseOpts.presentationExchange),
        });
        return response;
    }
    async verify(verifyOpts) {
        var _a;
        // Merge payloads checks for inconsistencies in properties which are present in both the auth request and request object
        const merged = await this.mergedPayloads(true);
        if (verifyOpts.state && merged.state !== verifyOpts.state) {
            throw Error(types_1.SIOPErrors.BAD_STATE);
        }
        const verifiedIdToken = await ((_a = this.idToken) === null || _a === void 0 ? void 0 : _a.verify(verifyOpts));
        const oid4vp = await (0, OpenID4VP_1.verifyPresentations)(this, verifyOpts);
        return Object.assign(Object.assign({ authorizationResponse: this, verifyOpts, correlationId: verifyOpts.correlationId }, (this.idToken ? { idToken: verifiedIdToken } : {})), (oid4vp ? { oid4vpSubmission: oid4vp } : {}));
    }
    get authorizationRequest() {
        return this._authorizationRequest;
    }
    get payload() {
        return this._payload;
    }
    get options() {
        return this._options;
    }
    get idToken() {
        return this._idToken;
    }
    async getMergedProperty(key, consistencyCheck) {
        const merged = await this.mergedPayloads(consistencyCheck);
        return merged[key];
    }
    async mergedPayloads(consistencyCheck) {
        var _a;
        const idTokenPayload = await ((_a = this.idToken) === null || _a === void 0 ? void 0 : _a.payload());
        if (consistencyCheck !== false && idTokenPayload) {
            Object.entries(idTokenPayload).forEach((entry) => {
                if (typeof entry[0] === 'string' && this.payload[entry[0]] && this.payload[entry[0]] !== entry[1]) {
                    throw Error(`Mismatch in Authorization Request and Request object value for ${entry[0]}`);
                }
            });
        }
        return Object.assign(Object.assign({}, this.payload), idTokenPayload);
    }
}
exports.AuthorizationResponse = AuthorizationResponse;
