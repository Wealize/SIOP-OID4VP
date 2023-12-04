"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRequestRegistration = exports.assertValidRequestRegistrationOpts = void 0;
const helpers_1 = require("../helpers");
const types_1 = require("../types");
/*const ajv = new Ajv({ allowUnionTypes: true, strict: false });
const validateRPRegistrationMetadata = ajv.compile(RPRegistrationMetadataPayloadSchema);*/
const assertValidRequestRegistrationOpts = (opts) => {
    if (!opts) {
        throw new Error(types_1.SIOPErrors.REGISTRATION_NOT_SET);
    }
    else if (opts.passBy !== types_1.PassBy.REFERENCE && opts.passBy !== types_1.PassBy.VALUE) {
        throw new Error(types_1.SIOPErrors.REGISTRATION_OBJECT_TYPE_NOT_SET);
    }
    else if (opts.passBy === types_1.PassBy.REFERENCE && !opts.reference_uri) {
        throw new Error(types_1.SIOPErrors.NO_REFERENCE_URI);
    }
};
exports.assertValidRequestRegistrationOpts = assertValidRequestRegistrationOpts;
const createRequestRegistrationPayload = async (opts, metadataPayload, version) => {
    (0, exports.assertValidRequestRegistrationOpts)(opts);
    if (opts.passBy == types_1.PassBy.VALUE) {
        if (version >= types_1.SupportedVersion.SIOPv2_D11.valueOf()) {
            return { client_metadata: (0, helpers_1.removeNullUndefined)(metadataPayload) };
        }
        else {
            return { registration: (0, helpers_1.removeNullUndefined)(metadataPayload) };
        }
    }
    else {
        if (version >= types_1.SupportedVersion.SIOPv2_D11.valueOf()) {
            return {
                client_metadata_uri: opts.reference_uri,
            };
        }
        else {
            return {
                registration_uri: opts.reference_uri,
            };
        }
    }
};
const createRequestRegistration = async (clientMetadataOpts, createRequestOpts) => {
    const metadata = createRPRegistrationMetadataPayload(clientMetadataOpts);
    const payload = await createRequestRegistrationPayload(clientMetadataOpts, metadata, createRequestOpts.version);
    return {
        payload,
        metadata,
        createRequestOpts,
        clientMetadataOpts,
    };
};
exports.createRequestRegistration = createRequestRegistration;
const createRPRegistrationMetadataPayload = (opts) => {
    const rpRegistrationMetadataPayload = {
        id_token_signing_alg_values_supported: opts.idTokenSigningAlgValuesSupported,
        request_object_signing_alg_values_supported: opts.requestObjectSigningAlgValuesSupported,
        response_types_supported: opts.responseTypesSupported,
        scopes_supported: opts.scopesSupported,
        subject_types_supported: opts.subjectTypesSupported,
        subject_syntax_types_supported: opts.subject_syntax_types_supported || ['did:web:', 'did:ion:'],
        vp_formats: opts.vpFormatsSupported,
        client_name: opts.clientName,
        logo_uri: opts.logo_uri,
        tos_uri: opts.tos_uri,
        client_purpose: opts.clientPurpose,
        client_id: opts.client_id,
    };
    const languageTagEnabledFieldsNamesMapping = new Map();
    languageTagEnabledFieldsNamesMapping.set('clientName', 'client_name');
    languageTagEnabledFieldsNamesMapping.set('clientPurpose', 'client_purpose');
    const languageTaggedFields = helpers_1.LanguageTagUtils.getLanguageTaggedPropertiesMapped(opts, languageTagEnabledFieldsNamesMapping);
    languageTaggedFields.forEach((value, key) => {
        rpRegistrationMetadataPayload[key] = value;
    });
    return (0, helpers_1.removeNullUndefined)(rpRegistrationMetadataPayload);
};
