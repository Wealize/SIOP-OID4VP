"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createVerifyRequestOptsFromBuilderOrExistingOpts = exports.createResponseOptsFromBuilderOrExistingOpts = void 0;
const did_1 = require("../did");
const helpers_1 = require("../helpers");
const schemas_1 = require("../schemas");
const types_1 = require("../types");
const createResponseOptsFromBuilderOrExistingOpts = (opts) => {
    var _a, _b, _c;
    if (((_a = opts === null || opts === void 0 ? void 0 : opts.builder) === null || _a === void 0 ? void 0 : _a.resolvers.size) && ((_c = (_b = opts.builder) === null || _b === void 0 ? void 0 : _b.responseRegistration) === null || _c === void 0 ? void 0 : _c.subject_syntax_types_supported)) {
        opts.builder.responseRegistration.subject_syntax_types_supported = (0, did_1.mergeAllDidMethods)(opts.builder.responseRegistration.subject_syntax_types_supported, opts.builder.resolvers);
    }
    let responseOpts;
    if (opts.builder) {
        responseOpts = Object.assign({ registration: Object.assign({ issuer: opts.builder.issuer }, opts.builder.responseRegistration), expiresIn: opts.builder.expiresIn, signature: opts.builder.signature, responseMode: opts.builder.responseMode }, ((responseOpts === null || responseOpts === void 0 ? void 0 : responseOpts.version)
            ? { version: responseOpts.version }
            : Array.isArray(opts.builder.supportedVersions) && opts.builder.supportedVersions.length > 0
                ? { version: opts.builder.supportedVersions[0] }
                : {}));
        if (!responseOpts.registration.passBy) {
            responseOpts.registration.passBy = types_1.PassBy.VALUE;
        }
        const languageTagEnabledFieldsNames = ['clientName', 'clientPurpose'];
        const languageTaggedFields = helpers_1.LanguageTagUtils.getLanguageTaggedProperties(opts.builder.responseRegistration, languageTagEnabledFieldsNames);
        languageTaggedFields.forEach((value, key) => {
            responseOpts.registration[key] = value;
        });
    }
    else {
        responseOpts = Object.assign({}, opts.responseOpts);
    }
    const valid = (0, schemas_1.AuthorizationResponseOptsSchema)(responseOpts);
    if (!valid) {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        //@ts-ignore
        throw new Error('OP builder validation error: ' + JSON.stringify(schemas_1.AuthorizationResponseOptsSchema.errors));
    }
    return responseOpts;
};
exports.createResponseOptsFromBuilderOrExistingOpts = createResponseOptsFromBuilderOrExistingOpts;
const createVerifyRequestOptsFromBuilderOrExistingOpts = (opts) => {
    var _a, _b;
    if (((_a = opts === null || opts === void 0 ? void 0 : opts.builder) === null || _a === void 0 ? void 0 : _a.resolvers.size) && ((_b = opts.builder) === null || _b === void 0 ? void 0 : _b.responseRegistration)) {
        opts.builder.responseRegistration.subject_syntax_types_supported = (0, did_1.mergeAllDidMethods)(opts.builder.responseRegistration.subject_syntax_types_supported, opts.builder.resolvers);
    }
    let resolver;
    if (opts.builder) {
        resolver = (0, did_1.getResolverUnion)(opts.builder.customResolver, opts.builder.responseRegistration.subject_syntax_types_supported, opts.builder.resolvers);
    }
    return opts.builder
        ? {
            verification: {
                mode: types_1.VerificationMode.INTERNAL,
                checkLinkedDomain: opts.builder.checkLinkedDomain,
                wellknownDIDVerifyCallback: opts.builder.wellknownDIDVerifyCallback,
                resolveOpts: {
                    subjectSyntaxTypesSupported: opts.builder.responseRegistration.subject_syntax_types_supported,
                    resolver: resolver,
                },
            },
            supportedVersions: opts.builder.supportedVersions,
            correlationId: undefined,
        }
        : opts.verifyOpts;
};
exports.createVerifyRequestOptsFromBuilderOrExistingOpts = createVerifyRequestOptsFromBuilderOrExistingOpts;
