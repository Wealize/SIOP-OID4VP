"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OP = void 0;
const uuid_1 = require("uuid");
const authorization_request_1 = require("../authorization-request");
const Opts_1 = require("../authorization-request/Opts");
const authorization_response_1 = require("../authorization-response");
const helpers_1 = require("../helpers");
const SIOPSpecVersion_1 = require("../helpers/SIOPSpecVersion");
const types_1 = require("../types");
const OPBuilder_1 = require("./OPBuilder");
const Opts_2 = require("./Opts");
// The OP publishes the formats it supports using the vp_formats_supported metadata parameter as defined above in its "openid-configuration".
class OP {
    constructor(opts) {
        var _a;
        this._createResponseOptions = Object.assign({}, (0, Opts_2.createResponseOptsFromBuilderOrExistingOpts)(opts));
        this._verifyRequestOptions = Object.assign({}, (0, Opts_2.createVerifyRequestOptsFromBuilderOrExistingOpts)(opts));
        this._eventEmitter = (_a = opts.builder) === null || _a === void 0 ? void 0 : _a.eventEmitter;
    }
    /**
     * This method tries to infer the SIOP specs version based on the request payload.
     * If the version cannot be inferred or is not supported it throws an exception.
     * This method needs to be called to ensure the OP can handle the request
     * @param requestJwtOrUri
     * @param requestOpts
     */
    async verifyAuthorizationRequest(requestJwtOrUri, requestOpts) {
        const correlationId = (requestOpts === null || requestOpts === void 0 ? void 0 : requestOpts.correlationId) || (0, uuid_1.v4)();
        const authorizationRequest = await authorization_request_1.AuthorizationRequest.fromUriOrJwt(requestJwtOrUri)
            .then((result) => {
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_REQUEST_RECEIVED_SUCCESS, { correlationId, subject: result });
            return result;
        })
            .catch((error) => {
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_REQUEST_RECEIVED_FAILED, {
                correlationId,
                subject: requestJwtOrUri,
                error,
            });
            throw error;
        });
        return authorizationRequest
            .verify(this.newVerifyAuthorizationRequestOpts(Object.assign(Object.assign({}, requestOpts), { correlationId })))
            .then((verifiedAuthorizationRequest) => {
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_REQUEST_VERIFIED_SUCCESS, {
                correlationId,
                subject: verifiedAuthorizationRequest.authorizationRequest,
            });
            return verifiedAuthorizationRequest;
        })
            .catch((error) => {
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_REQUEST_VERIFIED_FAILED, {
                correlationId,
                subject: authorizationRequest,
                error,
            });
            throw error;
        });
    }
    async createAuthorizationResponse(verifiedAuthorizationRequest, responseOpts) {
        if (verifiedAuthorizationRequest.correlationId &&
            (responseOpts === null || responseOpts === void 0 ? void 0 : responseOpts.correlationId) &&
            verifiedAuthorizationRequest.correlationId !== responseOpts.correlationId) {
            throw new Error(`Request correlation id ${verifiedAuthorizationRequest.correlationId} is different from option correlation id ${responseOpts.correlationId}`);
        }
        let version = responseOpts === null || responseOpts === void 0 ? void 0 : responseOpts.version;
        const rpSupportedVersions = (0, SIOPSpecVersion_1.authorizationRequestVersionDiscovery)(await verifiedAuthorizationRequest.authorizationRequest.mergedPayloads());
        if (version && rpSupportedVersions.length > 0 && !rpSupportedVersions.includes(version)) {
            throw Error(`RP does not support spec version ${version}, supported versions: ${rpSupportedVersions.toString()}`);
        }
        else if (!version) {
            version = rpSupportedVersions.reduce((previous, current) => (current.valueOf() > previous.valueOf() ? current : previous), types_1.SupportedVersion.SIOPv2_ID1);
        }
        const correlationId = (responseOpts === null || responseOpts === void 0 ? void 0 : responseOpts.correlationId) || verifiedAuthorizationRequest.correlationId || (0, uuid_1.v4)();
        try {
            const response = await authorization_response_1.AuthorizationResponse.fromVerifiedAuthorizationRequest(verifiedAuthorizationRequest, this.newAuthorizationResponseOpts(Object.assign(Object.assign({}, responseOpts), { version,
                correlationId })), verifiedAuthorizationRequest.verifyOpts);
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_RESPONSE_CREATE_SUCCESS, {
                correlationId,
                subject: response,
            });
            return { correlationId, response, redirectURI: verifiedAuthorizationRequest.redirectURI };
        }
        catch (error) {
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_RESPONSE_CREATE_FAILED, {
                correlationId,
                subject: verifiedAuthorizationRequest.authorizationRequest,
                error,
            });
            throw error;
        }
    }
    // TODO SK Can you please put some documentation on it?
    async submitAuthorizationResponse(authorizationResponse) {
        var _a, _b, _c, _d;
        const { correlationId, response } = authorizationResponse;
        if (!correlationId) {
            throw Error('No correlation Id provided');
        }
        if (!response ||
            (((_a = response.options) === null || _a === void 0 ? void 0 : _a.responseMode) &&
                !(((_b = response.options) === null || _b === void 0 ? void 0 : _b.responseMode) === types_1.ResponseMode.POST || ((_c = response.options) === null || _c === void 0 ? void 0 : _c.responseMode) === types_1.ResponseMode.FORM_POST))) {
            throw new Error(types_1.SIOPErrors.BAD_PARAMS);
        }
        const payload = await response.payload;
        const idToken = await ((_d = response.idToken) === null || _d === void 0 ? void 0 : _d.payload());
        const redirectURI = authorizationResponse.redirectURI || (idToken === null || idToken === void 0 ? void 0 : idToken.aud);
        if (!redirectURI) {
            throw Error('No redirect URI present');
        }
        const authResponseAsURI = (0, helpers_1.encodeJsonAsURI)(payload);
        return (0, helpers_1.post)(redirectURI, authResponseAsURI, { contentType: types_1.ContentType.FORM_URL_ENCODED })
            .then((result) => {
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_RESPONSE_SENT_SUCCESS, { correlationId, subject: response });
            return result.origResponse;
        })
            .catch((error) => {
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_RESPONSE_SENT_FAILED, { correlationId, subject: response, error });
            throw error;
        });
    }
    /**
     * Create an Authentication Request Payload from a URI string
     *
     * @param encodedUri
     */
    async parseAuthorizationRequestURI(encodedUri) {
        const { scheme, requestObjectJwt, authorizationRequestPayload, registrationMetadata } = await authorization_request_1.URI.parseAndResolve(encodedUri);
        return {
            encodedUri,
            encodingFormat: types_1.UrlEncodingFormat.FORM_URL_ENCODED,
            scheme: scheme,
            requestObjectJwt,
            authorizationRequestPayload,
            registration: registrationMetadata,
        };
    }
    newAuthorizationResponseOpts(opts) {
        var _a, _b, _c, _d, _e, _f, _g, _h;
        const version = (_a = opts.version) !== null && _a !== void 0 ? _a : this._createResponseOptions.version;
        let issuer = (_b = opts.issuer) !== null && _b !== void 0 ? _b : (_d = (_c = this._createResponseOptions) === null || _c === void 0 ? void 0 : _c.registration) === null || _d === void 0 ? void 0 : _d.issuer;
        if (!issuer && version) {
            if (version === types_1.SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1) {
                issuer = types_1.ResponseIss.JWT_VC_PRESENTATION_V1;
            }
            else if (version === types_1.SupportedVersion.SIOPv2_ID1) {
                issuer = types_1.ResponseIss.SELF_ISSUED_V2;
            }
        }
        if (!issuer) {
            throw Error(`No issuer value present. Either use IDv1, JWT VC Presentation profile version, or provide a DID as issuer value`);
        }
        // We are taking the whole presentationExchange object from a certain location
        const presentationExchange = (_e = opts.presentationExchange) !== null && _e !== void 0 ? _e : this._createResponseOptions.presentationExchange;
        return Object.assign(Object.assign(Object.assign(Object.assign(Object.assign({}, this._createResponseOptions), opts), { signature: Object.assign(Object.assign({}, (_f = this._createResponseOptions) === null || _f === void 0 ? void 0 : _f.signature), opts.signature) }), (presentationExchange && { presentationExchange })), { registration: Object.assign(Object.assign({}, (_g = this._createResponseOptions) === null || _g === void 0 ? void 0 : _g.registration), { issuer }), redirectUri: (_h = opts.audience) !== null && _h !== void 0 ? _h : this._createResponseOptions.redirectUri });
    }
    newVerifyAuthorizationRequestOpts(requestOpts) {
        const verification = Object.assign(Object.assign(Object.assign({}, this._verifyRequestOptions), requestOpts), { verification: (0, Opts_1.mergeVerificationOpts)(this._verifyRequestOptions, requestOpts), correlationId: requestOpts.correlationId });
        return verification;
    }
    async emitEvent(type, payload) {
        if (this._eventEmitter) {
            this._eventEmitter.emit(type, new types_1.AuthorizationEvent(payload));
        }
    }
    addEventListener(register) {
        if (!this._eventEmitter) {
            throw Error('Cannot add listeners if no event emitter is available');
        }
        const events = Array.isArray(register.event) ? register.event : [register.event];
        for (const event of events) {
            this._eventEmitter.addListener(event, register.listener);
        }
    }
    static fromOpts(responseOpts, verifyOpts) {
        return new OP({ responseOpts, verifyOpts });
    }
    static builder() {
        return new OPBuilder_1.OPBuilder();
    }
    get createResponseOptions() {
        return this._createResponseOptions;
    }
    get verifyRequestOptions() {
        return this._verifyRequestOptions;
    }
}
exports.OP = OP;
