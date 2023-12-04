"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthorizationRequest = void 0;
const PresentationExchange_1 = require("../authorization-response/PresentationExchange");
const did_1 = require("../did");
const helpers_1 = require("../helpers");
const SIOPSpecVersion_1 = require("../helpers/SIOPSpecVersion");
const request_object_1 = require("../request-object");
const types_1 = require("../types");
const Opts_1 = require("./Opts");
const Payload_1 = require("./Payload");
const URI_1 = require("./URI");
class AuthorizationRequest {
    constructor(payload, requestObject, opts, uri) {
        this._options = opts;
        this._payload = (0, helpers_1.removeNullUndefined)(payload);
        this._requestObject = requestObject;
        this._uri = uri;
    }
    static async fromUriOrJwt(jwtOrUri) {
        if (!jwtOrUri) {
            throw Error(types_1.SIOPErrors.NO_REQUEST);
        }
        return typeof jwtOrUri === 'string' && jwtOrUri.startsWith('ey')
            ? await AuthorizationRequest.fromJwt(jwtOrUri)
            : await AuthorizationRequest.fromURI(jwtOrUri);
    }
    static async fromPayload(payload) {
        if (!payload) {
            throw Error(types_1.SIOPErrors.NO_REQUEST);
        }
        const requestObject = await request_object_1.RequestObject.fromAuthorizationRequestPayload(payload);
        return new AuthorizationRequest(payload, requestObject);
    }
    static async fromOpts(opts, requestObject) {
        if (!opts || !opts.requestObject) {
            throw Error(types_1.SIOPErrors.BAD_PARAMS);
        }
        (0, Opts_1.assertValidAuthorizationRequestOpts)(opts);
        const requestObjectArg = opts.requestObject.passBy !== types_1.PassBy.NONE ? (requestObject ? requestObject : await request_object_1.RequestObject.fromOpts(opts)) : undefined;
        const requestPayload = (opts === null || opts === void 0 ? void 0 : opts.payload) ? await (0, Payload_1.createAuthorizationRequestPayload)(opts, requestObjectArg) : undefined;
        return new AuthorizationRequest(requestPayload, requestObjectArg, opts);
    }
    get payload() {
        return this._payload;
    }
    get requestObject() {
        return this._requestObject;
    }
    get options() {
        return this._options;
    }
    hasRequestObject() {
        return this.requestObject !== undefined;
    }
    async getSupportedVersion() {
        var _a, _b, _c, _d, _e;
        if ((_a = this.options) === null || _a === void 0 ? void 0 : _a.version) {
            return this.options.version;
        }
        else if (((_c = (_b = this._uri) === null || _b === void 0 ? void 0 : _b.encodedUri) === null || _c === void 0 ? void 0 : _c.startsWith(types_1.Schema.OPENID_VC)) || ((_e = (_d = this._uri) === null || _d === void 0 ? void 0 : _d.scheme) === null || _e === void 0 ? void 0 : _e.startsWith(types_1.Schema.OPENID_VC))) {
            return types_1.SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1;
        }
        return (await this.getSupportedVersionsFromPayload())[0];
    }
    async getSupportedVersionsFromPayload() {
        const mergedPayload = Object.assign(Object.assign({}, this.payload), (await this.requestObject.getPayload()));
        return (0, SIOPSpecVersion_1.authorizationRequestVersionDiscovery)(mergedPayload);
    }
    async uri() {
        if (!this._uri) {
            this._uri = await URI_1.URI.fromAuthorizationRequest(this);
        }
        return this._uri;
    }
    /**
     * Verifies a SIOP Request JWT on OP side
     *
     * @param opts
     */
    async verify(opts) {
        var _a, _b;
        (0, Opts_1.assertValidVerifyAuthorizationRequestOpts)(opts);
        let requestObjectPayload;
        let verifiedJwt;
        const jwt = await this.requestObjectJwt();
        if (jwt) {
            (0, did_1.parseJWT)(jwt);
            const resolver = (0, did_1.getResolver)(opts.verification.resolveOpts);
            const options = Object.assign(Object.assign({}, (_b = (_a = opts.verification) === null || _a === void 0 ? void 0 : _a.resolveOpts) === null || _b === void 0 ? void 0 : _b.jwtVerifyOpts), { resolver, audience: (0, did_1.getAudience)(jwt) });
            verifiedJwt = await (0, did_1.verifyDidJWT)(jwt, resolver, options);
            if (!verifiedJwt || !verifiedJwt.payload) {
                throw Error(types_1.SIOPErrors.ERROR_VERIFYING_SIGNATURE);
            }
            requestObjectPayload = verifiedJwt.payload;
            if (this.hasRequestObject() && !this.payload.request_uri) {
                // Put back the request object as that won't be present yet
                this.payload.request = jwt;
            }
        }
        // AuthorizationRequest.assertValidRequestObject(origAuthenticationRequest);
        // We use the orig request for default values, but the JWT payload contains signed request object properties
        const mergedPayload = Object.assign(Object.assign({}, this.payload), requestObjectPayload);
        if (opts.state && mergedPayload.state !== opts.state) {
            throw new Error(`${types_1.SIOPErrors.BAD_STATE} payload: ${mergedPayload.state}, supplied: ${opts.state}`);
        }
        else if (opts.nonce && mergedPayload.nonce !== opts.nonce) {
            throw new Error(`${types_1.SIOPErrors.BAD_NONCE} payload: ${mergedPayload.nonce}, supplied: ${opts.nonce}`);
        }
        const discoveryKey = mergedPayload['registration'] || mergedPayload['registration_uri'] ? 'registration' : 'client_metadata';
        let registrationMetadataPayload;
        if (mergedPayload[discoveryKey] || mergedPayload[`${discoveryKey}_uri`]) {
            registrationMetadataPayload = await (0, helpers_1.fetchByReferenceOrUseByValue)(mergedPayload[`${discoveryKey}_uri`], mergedPayload[discoveryKey]);
            (0, Payload_1.assertValidRPRegistrationMedataPayload)(registrationMetadataPayload);
            // TODO: We need to do something with the metadata probably
        }
        await (0, Payload_1.checkWellknownDIDFromRequest)(mergedPayload, opts);
        const presentationDefinitions = await PresentationExchange_1.PresentationExchange.findValidPresentationDefinitions(mergedPayload, await this.getSupportedVersion());
        return Object.assign(Object.assign({}, verifiedJwt), { redirectURI: mergedPayload.redirect_uri, correlationId: opts.correlationId, authorizationRequest: this, verifyOpts: opts, presentationDefinitions,
            registrationMetadataPayload, requestObject: this.requestObject, authorizationRequestPayload: this.payload, versions: await this.getSupportedVersionsFromPayload() });
    }
    static async verify(requestOrUri, verifyOpts) {
        (0, Opts_1.assertValidVerifyAuthorizationRequestOpts)(verifyOpts);
        const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(requestOrUri);
        return await authorizationRequest.verify(verifyOpts);
    }
    async requestObjectJwt() {
        var _a;
        return await ((_a = this.requestObject) === null || _a === void 0 ? void 0 : _a.toJwt());
    }
    static async fromJwt(jwt) {
        if (!jwt) {
            throw Error(types_1.SIOPErrors.BAD_PARAMS);
        }
        const requestObject = await request_object_1.RequestObject.fromJwt(jwt);
        const payload = Object.assign({}, (await requestObject.getPayload()));
        // Although this was a RequestObject we instantiate it as AuthzRequest and then copy in the JWT as the request Object
        payload.request = jwt;
        return new AuthorizationRequest(Object.assign({}, payload), requestObject);
    }
    static async fromURI(uri) {
        if (!uri) {
            throw Error(types_1.SIOPErrors.BAD_PARAMS);
        }
        const uriObject = typeof uri === 'string' ? await URI_1.URI.fromUri(uri) : uri;
        const requestObject = await request_object_1.RequestObject.fromJwt(uriObject.requestObjectJwt);
        return new AuthorizationRequest(uriObject.authorizationRequestPayload, requestObject, undefined, uriObject);
    }
    async toStateInfo() {
        var _a, _b;
        const requestObject = await this.requestObject.getPayload();
        return {
            client_id: this.options.clientMetadata.client_id,
            iat: (_a = requestObject.iat) !== null && _a !== void 0 ? _a : this.payload.iat,
            nonce: (_b = requestObject.nonce) !== null && _b !== void 0 ? _b : this.payload.nonce,
            state: this.payload.state,
        };
    }
    async containsResponseType(singleType) {
        const responseType = await this.getMergedProperty('response_type');
        return (responseType === null || responseType === void 0 ? void 0 : responseType.includes(singleType)) === true;
    }
    async getMergedProperty(key) {
        const merged = await this.mergedPayloads();
        return merged[key];
    }
    async mergedPayloads() {
        return Object.assign(Object.assign({}, this.payload), (await this.requestObject.getPayload()));
    }
    async getPresentationDefinitions(version) {
        return await PresentationExchange_1.PresentationExchange.findValidPresentationDefinitions(await this.mergedPayloads(), version);
    }
}
exports.AuthorizationRequest = AuthorizationRequest;
