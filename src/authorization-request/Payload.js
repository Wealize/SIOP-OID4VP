"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkWellknownDIDFromRequest = exports.assertValidRPRegistrationMedataPayload = exports.createAuthorizationRequestPayload = exports.createPresentationDefinitionClaimsProperties = void 0;
const pex_1 = require("@sphereon/pex");
const did_1 = require("../did");
const helpers_1 = require("../helpers");
const Opts_1 = require("../rp/Opts");
const schemas_1 = require("../schemas");
const types_1 = require("../types");
const RequestRegistration_1 = require("./RequestRegistration");
const types_2 = require("./types");
const createPresentationDefinitionClaimsProperties = (opts) => {
    if (!opts || !opts.vp_token || (!opts.vp_token.presentation_definition && !opts.vp_token.presentation_definition_uri)) {
        return undefined;
    }
    const discoveryResult = pex_1.PEX.definitionVersionDiscovery(opts.vp_token.presentation_definition);
    if (discoveryResult.error) {
        throw new Error(types_1.SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }
    return Object.assign(Object.assign({}, (opts.id_token ? { id_token: opts.id_token } : {})), ((opts.vp_token.presentation_definition || opts.vp_token.presentation_definition_uri) && {
        vp_token: Object.assign(Object.assign({}, (!opts.vp_token.presentation_definition_uri && { presentation_definition: opts.vp_token.presentation_definition })), (opts.vp_token.presentation_definition_uri && { presentation_definition_uri: opts.vp_token.presentation_definition_uri })),
    }));
};
exports.createPresentationDefinitionClaimsProperties = createPresentationDefinitionClaimsProperties;
const createAuthorizationRequestPayload = async (opts, requestObject) => {
    var _a;
    const payload = opts.payload;
    const state = (_a = payload === null || payload === void 0 ? void 0 : payload.state) !== null && _a !== void 0 ? _a : undefined;
    const nonce = (payload === null || payload === void 0 ? void 0 : payload.nonce) ? (0, helpers_1.getNonce)(state, payload.nonce) : undefined;
    // TODO: if opts['registration] throw Error to get rid of test code using that key
    const clientMetadata = opts['registration'] ? opts['registration'] : opts.clientMetadata;
    const registration = await (0, RequestRegistration_1.createRequestRegistration)(clientMetadata, opts);
    const claims = opts.version >= types_1.SupportedVersion.SIOPv2_ID1 ? opts.payload.claims : (0, exports.createPresentationDefinitionClaimsProperties)(opts.payload.claims);
    const isRequestTarget = (0, Opts_1.isTargetOrNoTargets)(types_2.PropertyTarget.AUTHORIZATION_REQUEST, opts.requestObject.targets);
    const isRequestByValue = opts.requestObject.passBy === types_1.PassBy.VALUE;
    if (isRequestTarget && isRequestByValue && !requestObject) {
        throw Error(types_1.SIOPErrors.NO_JWT);
    }
    const request = isRequestByValue ? await requestObject.toJwt() : undefined;
    const authRequestPayload = Object.assign(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign({}, payload), (isRequestTarget && opts.requestObject.passBy === types_1.PassBy.REFERENCE ? { request_uri: opts.requestObject.reference_uri } : {})), (isRequestTarget && isRequestByValue && { request })), (nonce && { nonce })), (state && { state })), (registration.payload && (0, Opts_1.isTarget)(types_2.PropertyTarget.AUTHORIZATION_REQUEST, registration.clientMetadataOpts.targets) ? registration.payload : {})), (claims && { claims }));
    return (0, helpers_1.removeNullUndefined)(authRequestPayload);
};
exports.createAuthorizationRequestPayload = createAuthorizationRequestPayload;
const assertValidRPRegistrationMedataPayload = (regObj) => {
    if (regObj) {
        const valid = (0, schemas_1.RPRegistrationMetadataPayloadSchema)(regObj);
        if (!valid) {
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            //@ts-ignore
            throw new Error('Registration data validation error: ' + JSON.stringify(schemas_1.RPRegistrationMetadataPayloadSchema.errors));
        }
    }
    if ((regObj === null || regObj === void 0 ? void 0 : regObj.subject_syntax_types_supported) && regObj.subject_syntax_types_supported.length == 0) {
        throw new Error(`${types_1.SIOPErrors.VERIFY_BAD_PARAMS}`);
    }
};
exports.assertValidRPRegistrationMedataPayload = assertValidRPRegistrationMedataPayload;
const checkWellknownDIDFromRequest = async (authorizationRequestPayload, opts) => {
    if (authorizationRequestPayload.client_id.startsWith('did:')) {
        if (opts.verification.checkLinkedDomain && opts.verification.checkLinkedDomain != types_1.CheckLinkedDomain.NEVER) {
            await (0, did_1.validateLinkedDomainWithDid)(authorizationRequestPayload.client_id, opts.verification);
        }
        else if (!opts.verification.checkLinkedDomain && opts.verification.wellknownDIDVerifyCallback) {
            await (0, did_1.validateLinkedDomainWithDid)(authorizationRequestPayload.client_id, opts.verification);
        }
    }
};
exports.checkWellknownDIDFromRequest = checkWellknownDIDFromRequest;
