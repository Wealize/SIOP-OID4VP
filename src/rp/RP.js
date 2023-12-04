"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RP = void 0;
const uuid_1 = require("uuid");
const authorization_request_1 = require("../authorization-request");
const Opts_1 = require("../authorization-request/Opts");
const authorization_response_1 = require("../authorization-response");
const helpers_1 = require("../helpers");
const types_1 = require("../types");
const Opts_2 = require("./Opts");
const RPBuilder_1 = require("./RPBuilder");
class RP {
    get sessionManager() {
        return this._sessionManager;
    }
    constructor(opts) {
        var _a, _b;
        // const claims = opts.builder?.claims || opts.createRequestOpts?.payload.claims;
        const authReqOpts = (0, Opts_2.createRequestOptsFromBuilderOrExistingOpts)(opts);
        this._createRequestOptions = Object.assign(Object.assign({}, authReqOpts), { payload: Object.assign({}, authReqOpts.payload) });
        this._verifyResponseOptions = Object.assign({}, (0, Opts_2.createVerifyResponseOptsFromBuilderOrExistingOpts)(opts));
        this._eventEmitter = (_a = opts.builder) === null || _a === void 0 ? void 0 : _a.eventEmitter;
        this._sessionManager = (_b = opts.builder) === null || _b === void 0 ? void 0 : _b.sessionManager;
    }
    static fromRequestOpts(opts) {
        return new RP({ createRequestOpts: opts });
    }
    static builder(opts) {
        return RPBuilder_1.RPBuilder.newInstance(opts === null || opts === void 0 ? void 0 : opts.requestVersion);
    }
    async createAuthorizationRequest(opts) {
        const authorizationRequestOpts = this.newAuthorizationRequestOpts(opts);
        return authorization_request_1.AuthorizationRequest.fromOpts(authorizationRequestOpts)
            .then((authorizationRequest) => {
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_REQUEST_CREATED_SUCCESS, {
                correlationId: opts.correlationId,
                subject: authorizationRequest,
            });
            return authorizationRequest;
        })
            .catch((error) => {
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_REQUEST_CREATED_FAILED, {
                correlationId: opts.correlationId,
                error,
            });
            throw error;
        });
    }
    async createAuthorizationRequestURI(opts) {
        const authorizationRequestOpts = this.newAuthorizationRequestOpts(opts);
        return await authorization_request_1.URI.fromOpts(authorizationRequestOpts)
            .then(async (uri) => {
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_REQUEST_CREATED_SUCCESS, {
                correlationId: opts.correlationId,
                subject: await authorization_request_1.AuthorizationRequest.fromOpts(authorizationRequestOpts),
            });
            return uri;
        })
            .catch((error) => {
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_REQUEST_CREATED_FAILED, {
                correlationId: opts.correlationId,
                error,
            });
            throw error;
        });
    }
    async signalAuthRequestRetrieved(opts) {
        if (!this.sessionManager) {
            throw Error(`Cannot signal auth request retrieval when no session manager is registered`);
        }
        const state = await this.sessionManager.getRequestStateByCorrelationId(opts.correlationId, true);
        this.emitEvent((opts === null || opts === void 0 ? void 0 : opts.error) ? types_1.AuthorizationEvents.ON_AUTH_REQUEST_SENT_FAILED : types_1.AuthorizationEvents.ON_AUTH_REQUEST_SENT_SUCCESS, Object.assign(Object.assign({ correlationId: opts.correlationId }, (!(opts === null || opts === void 0 ? void 0 : opts.error) ? { subject: state.request } : {})), ((opts === null || opts === void 0 ? void 0 : opts.error) ? { error: opts.error } : {})));
    }
    async verifyAuthorizationResponse(authorizationResponsePayload, opts) {
        var _a;
        const state = (opts === null || opts === void 0 ? void 0 : opts.state) || this.verifyResponseOptions.state;
        let correlationId = (opts === null || opts === void 0 ? void 0 : opts.correlationId) || state;
        let authorizationResponse;
        try {
            authorizationResponse = await authorization_response_1.AuthorizationResponse.fromPayload(authorizationResponsePayload);
        }
        catch (error) {
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_RESPONSE_RECEIVED_FAILED, {
                correlationId: correlationId !== null && correlationId !== void 0 ? correlationId : (0, uuid_1.v4)(),
                subject: authorizationResponsePayload,
                error,
            });
            throw error;
        }
        try {
            const verifyAuthenticationResponseOpts = await this.newVerifyAuthorizationResponseOpts(authorizationResponse, Object.assign(Object.assign({}, opts), { correlationId }));
            correlationId = (_a = verifyAuthenticationResponseOpts.correlationId) !== null && _a !== void 0 ? _a : correlationId;
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_RESPONSE_RECEIVED_SUCCESS, {
                correlationId,
                subject: authorizationResponse,
            });
            const verifiedAuthorizationResponse = await authorizationResponse.verify(verifyAuthenticationResponseOpts);
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_SUCCESS, {
                correlationId,
                subject: authorizationResponse,
            });
            return verifiedAuthorizationResponse;
        }
        catch (error) {
            this.emitEvent(types_1.AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_FAILED, {
                correlationId,
                subject: authorizationResponse,
                error,
            });
            throw error;
        }
    }
    get createRequestOptions() {
        return this._createRequestOptions;
    }
    get verifyResponseOptions() {
        return this._verifyResponseOptions;
    }
    newAuthorizationRequestOpts(opts) {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o;
        const nonceWithTarget = typeof opts.nonce === 'string'
            ? { propertyValue: opts.nonce, targets: authorization_request_1.PropertyTarget.REQUEST_OBJECT }
            : opts === null || opts === void 0 ? void 0 : opts.nonce;
        const stateWithTarget = typeof opts.state === 'string'
            ? { propertyValue: opts.state, targets: authorization_request_1.PropertyTarget.REQUEST_OBJECT }
            : opts === null || opts === void 0 ? void 0 : opts.state;
        const claimsWithTarget = (opts === null || opts === void 0 ? void 0 : opts.claims) && !('propertyValue' in opts.claims)
            ? { propertyValue: opts.claims, targets: authorization_request_1.PropertyTarget.REQUEST_OBJECT }
            : opts === null || opts === void 0 ? void 0 : opts.claims;
        const version = (_a = opts === null || opts === void 0 ? void 0 : opts.version) !== null && _a !== void 0 ? _a : this._createRequestOptions.version;
        if (!version) {
            throw Error(types_1.SIOPErrors.NO_REQUEST_VERSION);
        }
        const referenceURI = (_b = opts.requestByReferenceURI) !== null && _b !== void 0 ? _b : (_d = (_c = this._createRequestOptions) === null || _c === void 0 ? void 0 : _c.requestObject) === null || _d === void 0 ? void 0 : _d.reference_uri;
        const redirectURI = (_g = (_e = opts.redirectURI) !== null && _e !== void 0 ? _e : (_f = this._createRequestOptions.requestObject.payload) === null || _f === void 0 ? void 0 : _f.redirect_uri) !== null && _g !== void 0 ? _g : (_h = this._createRequestOptions.payload) === null || _h === void 0 ? void 0 : _h.redirect_uri;
        if (!redirectURI) {
            throw Error(`A redirect URI is required at this point`);
        }
        else {
            if (((_j = this._createRequestOptions.requestObject.payload) === null || _j === void 0 ? void 0 : _j.redirect_uri) || !((_k = this._createRequestOptions.payload) === null || _k === void 0 ? void 0 : _k.redirect_uri)) {
                this._createRequestOptions.requestObject.payload.redirect_uri = redirectURI;
            }
            if ((_l = this._createRequestOptions.payload) === null || _l === void 0 ? void 0 : _l.redirect_uri) {
                this._createRequestOptions.payload.redirect_uri = redirectURI;
            }
        }
        const newOpts = Object.assign(Object.assign({}, this._createRequestOptions), { version });
        newOpts.requestObject.payload = (_m = newOpts.requestObject.payload) !== null && _m !== void 0 ? _m : {};
        newOpts.payload = (_o = newOpts.payload) !== null && _o !== void 0 ? _o : {};
        if (referenceURI) {
            if (newOpts.requestObject.passBy && newOpts.requestObject.passBy !== types_1.PassBy.REFERENCE) {
                throw Error(`Cannot pass by reference with uri ${referenceURI} when mode is ${newOpts.requestObject.passBy}`);
            }
            newOpts.requestObject.reference_uri = referenceURI;
            newOpts.requestObject.passBy = types_1.PassBy.REFERENCE;
        }
        const state = (0, helpers_1.getState)(stateWithTarget.propertyValue);
        if (stateWithTarget.propertyValue) {
            if ((0, Opts_2.isTargetOrNoTargets)(authorization_request_1.PropertyTarget.AUTHORIZATION_REQUEST, stateWithTarget.targets)) {
                newOpts.payload.state = state;
            }
            if ((0, Opts_2.isTargetOrNoTargets)(authorization_request_1.PropertyTarget.REQUEST_OBJECT, stateWithTarget.targets)) {
                newOpts.requestObject.payload.state = state;
            }
        }
        const nonce = (0, helpers_1.getNonce)(state, nonceWithTarget.propertyValue);
        if (nonceWithTarget.propertyValue) {
            if ((0, Opts_2.isTargetOrNoTargets)(authorization_request_1.PropertyTarget.AUTHORIZATION_REQUEST, nonceWithTarget.targets)) {
                newOpts.payload.nonce = nonce;
            }
            if ((0, Opts_2.isTargetOrNoTargets)(authorization_request_1.PropertyTarget.REQUEST_OBJECT, nonceWithTarget.targets)) {
                newOpts.requestObject.payload.nonce = nonce;
            }
        }
        if (claimsWithTarget === null || claimsWithTarget === void 0 ? void 0 : claimsWithTarget.propertyValue) {
            if ((0, Opts_2.isTargetOrNoTargets)(authorization_request_1.PropertyTarget.AUTHORIZATION_REQUEST, claimsWithTarget.targets)) {
                newOpts.payload.claims = Object.assign(Object.assign({}, newOpts.payload.claims), claimsWithTarget.propertyValue);
            }
            if ((0, Opts_2.isTargetOrNoTargets)(authorization_request_1.PropertyTarget.REQUEST_OBJECT, claimsWithTarget.targets)) {
                newOpts.requestObject.payload.claims = Object.assign(Object.assign({}, newOpts.requestObject.payload.claims), claimsWithTarget.propertyValue);
            }
        }
        return newOpts;
    }
    async newVerifyAuthorizationResponseOpts(authorizationResponse, opts) {
        var _a, _b, _c, _d, _e, _f, _g;
        let correlationId = (_a = opts === null || opts === void 0 ? void 0 : opts.correlationId) !== null && _a !== void 0 ? _a : this._verifyResponseOptions.correlationId;
        let state = (_b = opts === null || opts === void 0 ? void 0 : opts.state) !== null && _b !== void 0 ? _b : this._verifyResponseOptions.state;
        let nonce = (_c = opts === null || opts === void 0 ? void 0 : opts.nonce) !== null && _c !== void 0 ? _c : this._verifyResponseOptions.nonce;
        if (this.sessionManager) {
            const resNonce = (await authorizationResponse.getMergedProperty('nonce', false));
            const resState = (await authorizationResponse.getMergedProperty('state', false));
            correlationId = await this.sessionManager.getCorrelationIdByNonce(resNonce, false);
            if (!correlationId) {
                correlationId = await this.sessionManager.getCorrelationIdByState(resState, false);
            }
            if (!correlationId) {
                correlationId = nonce;
            }
            const requestState = await this.sessionManager.getRequestStateByCorrelationId(correlationId, false);
            if (requestState) {
                const reqNonce = await requestState.request.getMergedProperty('nonce');
                const reqState = await requestState.request.getMergedProperty('state');
                nonce = nonce !== null && nonce !== void 0 ? nonce : reqNonce;
                state = state !== null && state !== void 0 ? state : reqState;
            }
        }
        return Object.assign(Object.assign(Object.assign({}, this._verifyResponseOptions), opts), { correlationId, audience: (_f = (_e = (_d = opts === null || opts === void 0 ? void 0 : opts.audience) !== null && _d !== void 0 ? _d : this._verifyResponseOptions.audience) !== null && _e !== void 0 ? _e : this._verifyResponseOptions.verification.resolveOpts.jwtVerifyOpts.audience) !== null && _f !== void 0 ? _f : this._createRequestOptions.payload.client_id, state,
            nonce, verification: (0, Opts_1.mergeVerificationOpts)(this._verifyResponseOptions, opts), presentationDefinitions: (_g = opts === null || opts === void 0 ? void 0 : opts.presentationDefinitions) !== null && _g !== void 0 ? _g : this._verifyResponseOptions.presentationDefinitions });
    }
    async emitEvent(type, payload) {
        if (this._eventEmitter) {
            try {
                this._eventEmitter.emit(type, new types_1.AuthorizationEvent(payload));
            }
            catch (e) {
                //Let's make sure events do not cause control flow issues
                console.log(`Could not emit event ${type} for ${payload.correlationId} initial error if any: ${payload === null || payload === void 0 ? void 0 : payload.error}`);
            }
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
}
exports.RP = RP;
