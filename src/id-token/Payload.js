"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createIDTokenPayload = void 0;
const authorization_response_1 = require("../authorization-response");
const Opts_1 = require("../authorization-response/Opts");
const SIOPSpecVersion_1 = require("../helpers/SIOPSpecVersion");
const types_1 = require("../types");
const createIDTokenPayload = async (verifiedAuthorizationRequest, responseOpts) => {
    var _a, _b, _c;
    (0, Opts_1.assertValidResponseOpts)(responseOpts);
    const authorizationRequestPayload = await verifiedAuthorizationRequest.authorizationRequest.mergedPayloads();
    const requestObject = verifiedAuthorizationRequest.requestObject;
    if (!authorizationRequestPayload) {
        throw new Error(types_1.SIOPErrors.VERIFY_BAD_PARAMS);
    }
    const payload = await (0, authorization_response_1.mergeOAuth2AndOpenIdInRequestPayload)(authorizationRequestPayload, requestObject);
    const supportedDidMethods = verifiedAuthorizationRequest.registrationMetadataPayload.subject_syntax_types_supported.filter((sst) => sst.includes(types_1.SubjectSyntaxTypesSupportedValues.DID.valueOf()));
    const state = payload.state;
    const nonce = payload.nonce;
    const SEC_IN_MS = 1000;
    const rpSupportedVersions = (0, SIOPSpecVersion_1.authorizationRequestVersionDiscovery)(payload);
    const maxRPVersion = rpSupportedVersions.reduce((previous, current) => (current.valueOf() > previous.valueOf() ? current : previous), types_1.SupportedVersion.SIOPv2_ID1);
    if (responseOpts.version && rpSupportedVersions.length > 0 && !rpSupportedVersions.includes(responseOpts.version)) {
        throw Error(`RP does not support spec version ${responseOpts.version}, supported versions: ${rpSupportedVersions.toString()}`);
    }
    const opVersion = (_a = responseOpts.version) !== null && _a !== void 0 ? _a : maxRPVersion;
    const idToken = {
        // fixme: ID11 does not use this static value anymore
        iss: (_c = (_b = responseOpts === null || responseOpts === void 0 ? void 0 : responseOpts.registration) === null || _b === void 0 ? void 0 : _b.issuer) !== null && _c !== void 0 ? _c : (opVersion === types_1.SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1 ? types_1.ResponseIss.JWT_VC_PRESENTATION_V1 : types_1.ResponseIss.SELF_ISSUED_V2),
        aud: responseOpts.audience || payload.client_id,
        iat: Math.round(Date.now() / SEC_IN_MS - 60 * SEC_IN_MS),
        exp: Math.round(Date.now() / SEC_IN_MS + (responseOpts.expiresIn || 600)),
        sub: responseOpts.signature.did,
        auth_time: payload.auth_time,
        nonce,
        state,
        // ...(responseOpts.presentationExchange?._vp_token ? { _vp_token: responseOpts.presentationExchange._vp_token } : {}),
    };
    if (supportedDidMethods.indexOf(types_1.SubjectSyntaxTypesSupportedValues.JWK_THUMBPRINT) != -1 && !responseOpts.signature.did) {
        const { thumbprint, subJwk } = await createThumbprintAndJWK(responseOpts);
        idToken['sub_jwk'] = subJwk;
        idToken.sub = thumbprint;
    }
    return idToken;
};
exports.createIDTokenPayload = createIDTokenPayload;
const createThumbprintAndJWK = async (resOpts) => {
    let thumbprint;
    let subJwk;
    /*  if (isInternalSignature(resOpts.signature)) {
      thumbprint = await getThumbprint(resOpts.signature.hexPrivateKey, resOpts.signature.did);
      subJwk = getPublicJWKFromHexPrivateKey(
        resOpts.signature.hexPrivateKey,
        resOpts.signature.kid || `${resOpts.signature.did}#key-1`,
        resOpts.signature.did
      );
    } else*/ if ((0, types_1.isSuppliedSignature)(resOpts.signature)) {
        // fixme: These are uninitialized. Probably we have to extend the supplied withSignature to provide these.
        return { thumbprint, subJwk };
    }
    else {
        throw new Error(types_1.SIOPErrors.SIGNATURE_OBJECT_TYPE_NOT_SET);
    }
};
