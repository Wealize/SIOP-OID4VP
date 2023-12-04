"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OPBuilder = void 0;
const events_1 = require("events");
const did_uni_client_1 = require("@sphereon/did-uni-client");
const did_resolver_1 = require("did-resolver");
const did_1 = require("../did");
const types_1 = require("../types");
const OP_1 = require("./OP");
class OPBuilder {
    constructor() {
        this.resolvers = new Map();
        this.responseMode = types_1.ResponseMode.POST;
        this.responseRegistration = {};
    }
    addDidMethod(didMethod, opts) {
        const method = didMethod.startsWith('did:') ? (0, did_1.getMethodFromDid)(didMethod) : didMethod;
        if (method === types_1.SubjectSyntaxTypesSupportedValues.DID.valueOf()) {
            opts ? this.addResolver('', new did_uni_client_1.UniResolver(Object.assign({}, opts))) : this.addResolver('', null);
        }
        opts ? this.addResolver(method, new did_resolver_1.Resolver((0, did_uni_client_1.getUniResolver)(method, Object.assign({}, opts)))) : this.addResolver(method, null);
        return this;
    }
    withIssuer(issuer) {
        this.issuer = issuer;
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
    /*withDid(did: string): OPBuilder {
      this.did = did;
      return this;
    }
  */
    withExpiresIn(expiresIn) {
        this.expiresIn = expiresIn;
        return this;
    }
    withCheckLinkedDomain(mode) {
        this.checkLinkedDomain = mode;
        return this;
    }
    withResponseMode(responseMode) {
        this.responseMode = responseMode;
        return this;
    }
    withRegistration(responseRegistration, targets) {
        this.responseRegistration = Object.assign({ targets }, responseRegistration);
        return this;
    }
    /*//TODO registration object creation
    authorizationEndpoint?: Schema.OPENID | string;
    scopesSupported?: Scope[] | Scope;
    subjectTypesSupported?: SubjectType[] | SubjectType;
    idTokenSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
    requestObjectSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  */
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
    withWellknownDIDVerifyCallback(wellknownDIDVerifyCallback) {
        this.wellknownDIDVerifyCallback = wellknownDIDVerifyCallback;
        return this;
    }
    withSupportedVersions(supportedVersions) {
        const versions = Array.isArray(supportedVersions) ? supportedVersions : [supportedVersions];
        for (const version of versions) {
            this.addSupportedVersion(version);
        }
        return this;
    }
    addSupportedVersion(supportedVersion) {
        if (!this.supportedVersions) {
            this.supportedVersions = [];
        }
        if (typeof supportedVersion === 'string') {
            this.supportedVersions.push(types_1.SupportedVersion[supportedVersion]);
        }
        else {
            this.supportedVersions.push(supportedVersion);
        }
        return this;
    }
    withPresentationSignCallback(presentationSignCallback) {
        this.presentationSignCallback = presentationSignCallback;
        return this;
    }
    withEventEmitter(eventEmitter) {
        this.eventEmitter = eventEmitter !== null && eventEmitter !== void 0 ? eventEmitter : new events_1.EventEmitter();
        return this;
    }
    build() {
        /*if (!this.responseRegistration) {
          throw Error('You need to provide response registrations values')
        } else */ /*if (!this.withSignature) {
          throw Error('You need to supply withSignature values');
        } else */ if (!this.supportedVersions || this.supportedVersions.length === 0) {
            this.supportedVersions = [types_1.SupportedVersion.SIOPv2_D11, types_1.SupportedVersion.SIOPv2_ID1, types_1.SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1];
        }
        // We ignore the private visibility, as we don't want others to use the OP directly
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        return new OP_1.OP({ builder: this });
    }
}
exports.OPBuilder = OPBuilder;
