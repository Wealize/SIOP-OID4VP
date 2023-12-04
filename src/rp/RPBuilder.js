"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RPBuilder = void 0;
const events_1 = require("events");
const did_uni_client_1 = require("@sphereon/did-uni-client");
const did_resolver_1 = require("did-resolver");
const authorization_request_1 = require("../authorization-request");
const did_1 = require("../did");
const types_1 = require("../types");
const Opts_1 = require("./Opts");
const RP_1 = require("./RP");
class RPBuilder {
    constructor(supportedRequestVersion) {
        this.resolvers = new Map();
        this._authorizationRequestPayload = {};
        this._requestObjectPayload = {};
        this.clientMetadata = undefined;
        if (supportedRequestVersion) {
            this.addSupportedVersion(supportedRequestVersion);
        }
    }
    withScope(scope, targets) {
        this._authorizationRequestPayload.scope = (0, Opts_1.assignIfAuth)({ propertyValue: scope, targets }, false);
        this._requestObjectPayload.scope = (0, Opts_1.assignIfRequestObject)({ propertyValue: scope, targets }, true);
        return this;
    }
    withResponseType(responseType, targets) {
        const propertyValue = Array.isArray(responseType) ? responseType.join(' ').trim() : responseType;
        this._authorizationRequestPayload.response_type = (0, Opts_1.assignIfAuth)({ propertyValue, targets }, false);
        this._requestObjectPayload.response_type = (0, Opts_1.assignIfRequestObject)({ propertyValue, targets }, true);
        return this;
    }
    withClientId(clientId, targets) {
        this._authorizationRequestPayload.client_id = (0, Opts_1.assignIfAuth)({ propertyValue: clientId, targets }, false);
        this._requestObjectPayload.client_id = (0, Opts_1.assignIfRequestObject)({ propertyValue: clientId, targets }, true);
        this.clientId = clientId;
        return this;
    }
    withIssuer(issuer, targets) {
        this._authorizationRequestPayload.iss = (0, Opts_1.assignIfAuth)({ propertyValue: issuer, targets }, false);
        this._requestObjectPayload.iss = (0, Opts_1.assignIfRequestObject)({ propertyValue: issuer, targets }, true);
        return this;
    }
    withPresentationVerification(presentationVerificationCallback) {
        this.presentationVerificationCallback = presentationVerificationCallback;
        return this;
    }
    withRevocationVerification(mode) {
        this.revocationVerification = mode;
        return this;
    }
    withRevocationVerificationCallback(callback) {
        this.revocationVerificationCallback = callback;
        return this;
    }
    withCustomResolver(resolver) {
        this.customResolver = resolver;
        return this;
    }
    addResolver(didMethod, resolver) {
        const qualifiedDidMethod = didMethod.startsWith('did:') ? (0, did_1.getMethodFromDid)(didMethod) : didMethod;
        this.resolvers.set(qualifiedDidMethod, resolver);
        return this;
    }
    withAuthorizationEndpoint(authorizationEndpoint, targets) {
        this._authorizationRequestPayload.authorization_endpoint = (0, Opts_1.assignIfAuth)({
            propertyValue: authorizationEndpoint,
            targets,
        }, false);
        this._requestObjectPayload.authorization_endpoint = (0, Opts_1.assignIfRequestObject)({
            propertyValue: authorizationEndpoint,
            targets,
        }, true);
        return this;
    }
    withCheckLinkedDomain(mode) {
        this.checkLinkedDomain = mode;
        return this;
    }
    addDidMethod(didMethod, opts) {
        const method = didMethod.startsWith('did:') ? (0, did_1.getMethodFromDid)(didMethod) : didMethod;
        if (method === types_1.SubjectSyntaxTypesSupportedValues.DID.valueOf()) {
            opts ? this.addResolver('', new did_uni_client_1.UniResolver(Object.assign({}, opts))) : this.addResolver('', null);
        }
        opts ? this.addResolver(method, new did_resolver_1.Resolver((0, did_uni_client_1.getUniResolver)(method, Object.assign({}, opts)))) : this.addResolver(method, null);
        return this;
    }
    withRedirectUri(redirectUri, targets) {
        this._authorizationRequestPayload.redirect_uri = (0, Opts_1.assignIfAuth)({ propertyValue: redirectUri, targets }, false);
        this._requestObjectPayload.redirect_uri = (0, Opts_1.assignIfRequestObject)({ propertyValue: redirectUri, targets }, true);
        return this;
    }
    withRequestByReference(referenceUri) {
        return this.withRequestBy(types_1.PassBy.REFERENCE, referenceUri /*, PropertyTarget.AUTHORIZATION_REQUEST*/);
    }
    withRequestByValue() {
        return this.withRequestBy(types_1.PassBy.VALUE, undefined /*, PropertyTarget.AUTHORIZATION_REQUEST*/);
    }
    withRequestBy(passBy, referenceUri /*, targets?: PropertyTargets*/) {
        if (passBy === types_1.PassBy.REFERENCE && !referenceUri) {
            throw Error('Cannot use pass by reference without a reference URI');
        }
        this.requestObjectBy = {
            passBy,
            reference_uri: referenceUri,
            targets: authorization_request_1.PropertyTarget.AUTHORIZATION_REQUEST,
        };
        return this;
    }
    withResponseMode(responseMode, targets) {
        this._authorizationRequestPayload.response_mode = (0, Opts_1.assignIfAuth)({ propertyValue: responseMode, targets }, false);
        this._requestObjectPayload.response_mode = (0, Opts_1.assignIfRequestObject)({ propertyValue: responseMode, targets }, true);
        return this;
    }
    withClientMetadata(clientMetadata, targets) {
        clientMetadata.targets = targets;
        if (this.getSupportedRequestVersion() < types_1.SupportedVersion.SIOPv2_D11) {
            this._authorizationRequestPayload.registration = (0, Opts_1.assignIfAuth)({
                propertyValue: clientMetadata,
                targets,
            }, false);
            this._requestObjectPayload.registration = (0, Opts_1.assignIfRequestObject)({
                propertyValue: clientMetadata,
                targets,
            }, true);
        }
        else {
            this._authorizationRequestPayload.client_metadata = (0, Opts_1.assignIfAuth)({
                propertyValue: clientMetadata,
                targets,
            }, false);
            this._requestObjectPayload.client_metadata = (0, Opts_1.assignIfRequestObject)({
                propertyValue: clientMetadata,
                targets,
            }, true);
        }
        this.clientMetadata = clientMetadata;
        //fixme: Add URL
        return this;
    }
    // Only internal and supplied signatures supported for now
    withSignature(signature) {
        this.signature = signature;
        return this;
    }
    withInternalSignature(hexPrivateKey, did, kid, alg, customJwtSigner) {
        this.withSignature({ hexPrivateKey, did, kid, alg, customJwtSigner });
        return this;
    }
    withSuppliedSignature(signature, did, kid, alg) {
        this.withSignature({ signature, did, kid, alg });
        return this;
    }
    withPresentationDefinition(definitionOpts, targets) {
        const { definition, definitionUri } = definitionOpts;
        const definitionProperties = {
            presentation_definition: definition,
            presentation_definition_uri: definitionUri,
        };
        if (this.getSupportedRequestVersion() < types_1.SupportedVersion.SIOPv2_D11) {
            const vp_token = Object.assign({}, definitionProperties);
            if ((0, Opts_1.isTarget)(authorization_request_1.PropertyTarget.AUTHORIZATION_REQUEST, targets)) {
                this._authorizationRequestPayload.claims = Object.assign(Object.assign({}, (this._authorizationRequestPayload.claims ? this._authorizationRequestPayload.claims : {})), { vp_token: vp_token });
            }
            if ((0, Opts_1.isTargetOrNoTargets)(authorization_request_1.PropertyTarget.REQUEST_OBJECT, targets)) {
                this._requestObjectPayload.claims = Object.assign(Object.assign({}, (this._requestObjectPayload.claims ? this._requestObjectPayload.claims : {})), { vp_token: vp_token });
            }
        }
        else {
            this._authorizationRequestPayload.presentation_definition = (0, Opts_1.assignIfAuth)({
                propertyValue: definition,
                targets,
            }, false);
            this._authorizationRequestPayload.presentation_definition_uri = (0, Opts_1.assignIfAuth)({
                propertyValue: definitionUri,
                targets,
            }, true);
            this._requestObjectPayload.presentation_definition = (0, Opts_1.assignIfRequestObject)({
                propertyValue: definition,
                targets,
            }, true);
            this._requestObjectPayload.presentation_definition_uri = (0, Opts_1.assignIfRequestObject)({
                propertyValue: definitionUri,
                targets,
            }, true);
        }
        return this;
    }
    withWellknownDIDVerifyCallback(wellknownDIDVerifyCallback) {
        this.wellknownDIDVerifyCallback = wellknownDIDVerifyCallback;
        return this;
    }
    initSupportedVersions() {
        if (!this.supportedVersions) {
            this.supportedVersions = [];
        }
    }
    addSupportedVersion(supportedVersion) {
        this.initSupportedVersions();
        if (!this.supportedVersions.includes(supportedVersion)) {
            this.supportedVersions.push(supportedVersion);
        }
        return this;
    }
    withSupportedVersions(supportedVersion) {
        const versions = Array.isArray(supportedVersion) ? supportedVersion : [supportedVersion];
        for (const version of versions) {
            this.addSupportedVersion(version);
        }
        return this;
    }
    withEventEmitter(eventEmitter) {
        this.eventEmitter = eventEmitter !== null && eventEmitter !== void 0 ? eventEmitter : new events_1.EventEmitter();
        return this;
    }
    withSessionManager(sessionManager) {
        this.sessionManager = sessionManager;
        return this;
    }
    getSupportedRequestVersion(requireVersion) {
        if (!this.supportedVersions || this.supportedVersions.length === 0) {
            if (requireVersion !== false) {
                throw Error('No supported version supplied/available');
            }
            return undefined;
        }
        return this.supportedVersions[0];
    }
    static newInstance(supportedVersion) {
        return new RPBuilder(supportedVersion);
    }
    build() {
        if (this.sessionManager && !this.eventEmitter) {
            throw Error('Please enable the event emitter on the RP when using a replay registry');
        }
        // We do not want others to directly use the RP class
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        return new RP_1.RP({ builder: this });
    }
    get authorizationRequestPayload() {
        return this._authorizationRequestPayload;
    }
    get requestObjectPayload() {
        return this._requestObjectPayload;
    }
}
exports.RPBuilder = RPBuilder;
