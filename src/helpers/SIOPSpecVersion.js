"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkSIOPSpecVersionSupported = exports.authorizationRequestVersionDiscovery = void 0;
const schemas_1 = require("../schemas");
const types_1 = require("../types");
const Errors_1 = __importDefault(require("../types/Errors"));
const validateJWTVCPresentationProfile = schemas_1.AuthorizationRequestPayloadVID1Schema;
function isJWTVC1Payload(authorizationRequest) {
    return (authorizationRequest.scope &&
        authorizationRequest.scope.toLowerCase().includes('openid') &&
        authorizationRequest.response_type &&
        authorizationRequest.response_type.toLowerCase().includes('id_token') &&
        authorizationRequest.response_mode &&
        authorizationRequest.response_mode.toLowerCase() === 'post' &&
        authorizationRequest.client_id &&
        authorizationRequest.client_id.toLowerCase().startsWith('did:') &&
        authorizationRequest.redirect_uri &&
        (authorizationRequest.registration_uri || authorizationRequest.registration) &&
        authorizationRequest.claims &&
        'vp_token' in authorizationRequest.claims);
}
function isID1Payload(authorizationRequest) {
    return (!authorizationRequest.client_metadata_uri &&
        !authorizationRequest.client_metadata &&
        !authorizationRequest.presentation_definition &&
        !authorizationRequest.presentation_definition_uri);
}
const authorizationRequestVersionDiscovery = (authorizationRequest) => {
    const versions = [];
    const authorizationRequestCopy = JSON.parse(JSON.stringify(authorizationRequest));
    const vd11Validation = (0, schemas_1.AuthorizationRequestPayloadVD11Schema)(authorizationRequestCopy);
    if (vd11Validation) {
        if (!authorizationRequestCopy.registration_uri &&
            !authorizationRequestCopy.registration &&
            !(authorizationRequest.claims && 'vp_token' in authorizationRequestCopy.claims)) {
            versions.push(types_1.SupportedVersion.SIOPv2_D11);
        }
    }
    const jwtVC1Validation = validateJWTVCPresentationProfile(authorizationRequestCopy);
    if (jwtVC1Validation && isJWTVC1Payload(authorizationRequest)) {
        versions.push(types_1.SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1);
    }
    const vid1Validation = (0, schemas_1.AuthorizationRequestPayloadVID1Schema)(authorizationRequestCopy);
    if (vid1Validation && isID1Payload(authorizationRequest)) {
        versions.push(types_1.SupportedVersion.SIOPv2_ID1);
    }
    if (versions.length === 0) {
        throw new Error(Errors_1.default.SIOP_VERSION_NOT_SUPPORTED);
    }
    return versions;
};
exports.authorizationRequestVersionDiscovery = authorizationRequestVersionDiscovery;
const checkSIOPSpecVersionSupported = async (payload, supportedVersions) => {
    const versions = (0, exports.authorizationRequestVersionDiscovery)(payload);
    if (!supportedVersions || supportedVersions.length === 0) {
        return versions;
    }
    return supportedVersions.filter((version) => versions.includes(version));
};
exports.checkSIOPSpecVersionSupported = checkSIOPSpecVersionSupported;
