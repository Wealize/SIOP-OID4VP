"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.assignIfRequestObject = exports.assignIfAuth = exports.isTarget = exports.isTargetOrNoTargets = exports.createVerifyResponseOptsFromBuilderOrExistingOpts = exports.createRequestOptsFromBuilderOrExistingOpts = void 0;
const authorization_request_1 = require("../authorization-request");
const did_1 = require("../did");
// import { CreateAuthorizationRequestOptsSchema } from '../schemas';
const types_1 = require("../types");
const createRequestOptsFromBuilderOrExistingOpts = (opts) => {
    var _a, _b;
    const version = opts.builder ? opts.builder.getSupportedRequestVersion() : opts.createRequestOpts.version;
    if (!version) {
        throw Error(types_1.SIOPErrors.NO_REQUEST_VERSION);
    }
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    const createRequestOpts = opts.builder
        ? {
            version,
            payload: Object.assign({}, opts.builder.authorizationRequestPayload),
            requestObject: Object.assign(Object.assign({}, opts.builder.requestObjectBy), { payload: Object.assign(Object.assign({}, opts.builder.requestObjectPayload), { subject_types_supported: (_a = opts.builder.clientMetadata) === null || _a === void 0 ? void 0 : _a.subjectTypesSupported, request_object_signing_alg_values_supported: (_b = opts.builder.clientMetadata) === null || _b === void 0 ? void 0 : _b.requestObjectSigningAlgValuesSupported }), signature: opts.builder.signature }),
            clientMetadata: opts.builder.clientMetadata,
        }
        : opts.createRequestOpts;
    /*const valid = true; // fixme: re-enable schema: CreateAuthorizationRequestOptsSchema(createRequestOpts);
    if (!valid) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      //@ts-ignore
      throw new Error('RP builder validation error: ' + JSON.stringify(CreateAuthorizationRequestOptsSchema.errors));
    }*/
    return createRequestOpts;
};
exports.createRequestOptsFromBuilderOrExistingOpts = createRequestOptsFromBuilderOrExistingOpts;
const createVerifyResponseOptsFromBuilderOrExistingOpts = (opts) => {
    var _a, _b, _c;
    if (((_a = opts === null || opts === void 0 ? void 0 : opts.builder) === null || _a === void 0 ? void 0 : _a.resolvers.size) && ((_b = opts.builder) === null || _b === void 0 ? void 0 : _b.clientMetadata)) {
        opts.builder.clientMetadata.subject_syntax_types_supported = (0, did_1.mergeAllDidMethods)(opts.builder.clientMetadata.subject_syntax_types_supported, opts.builder.resolvers);
    }
    let resolver;
    if (opts.builder) {
        resolver = (0, did_1.getResolverUnion)(opts.builder.customResolver, opts.builder.clientMetadata.subject_syntax_types_supported, opts.builder.resolvers);
    }
    return opts.builder
        ? {
            verification: {
                mode: types_1.VerificationMode.INTERNAL,
                checkLinkedDomain: opts.builder.checkLinkedDomain,
                wellknownDIDVerifyCallback: opts.builder.wellknownDIDVerifyCallback,
                presentationVerificationCallback: opts.builder.presentationVerificationCallback,
                resolveOpts: {
                    subjectSyntaxTypesSupported: opts.builder.clientMetadata.subject_syntax_types_supported,
                    resolver: resolver,
                },
                supportedVersions: opts.builder.supportedVersions,
                revocationOpts: {
                    revocationVerification: opts.builder.revocationVerification,
                    revocationVerificationCallback: opts.builder.revocationVerificationCallback,
                },
                replayRegistry: opts.builder.sessionManager,
            },
            audience: opts.builder.clientId || ((_c = opts.builder.clientMetadata) === null || _c === void 0 ? void 0 : _c.client_id),
        }
        : opts.verifyOpts;
};
exports.createVerifyResponseOptsFromBuilderOrExistingOpts = createVerifyResponseOptsFromBuilderOrExistingOpts;
const isTargetOrNoTargets = (searchTarget, targets) => {
    if (!targets) {
        return true;
    }
    return (0, exports.isTarget)(searchTarget, targets);
};
exports.isTargetOrNoTargets = isTargetOrNoTargets;
const isTarget = (searchTarget, targets) => {
    return Array.isArray(targets) ? targets.includes(searchTarget) : targets === searchTarget;
};
exports.isTarget = isTarget;
const assignIfAuth = (opt, isDefaultTarget) => {
    if (isDefaultTarget
        ? (0, exports.isTargetOrNoTargets)(authorization_request_1.PropertyTarget.AUTHORIZATION_REQUEST, opt.targets)
        : (0, exports.isTarget)(authorization_request_1.PropertyTarget.AUTHORIZATION_REQUEST, opt.targets)) {
        return opt.propertyValue;
    }
    return undefined;
};
exports.assignIfAuth = assignIfAuth;
const assignIfRequestObject = (opt, isDefaultTarget) => {
    if (isDefaultTarget ? (0, exports.isTargetOrNoTargets)(authorization_request_1.PropertyTarget.REQUEST_OBJECT, opt.targets) : (0, exports.isTarget)(authorization_request_1.PropertyTarget.REQUEST_OBJECT, opt.targets)) {
        return opt.propertyValue;
    }
    return undefined;
};
exports.assignIfRequestObject = assignIfRequestObject;
