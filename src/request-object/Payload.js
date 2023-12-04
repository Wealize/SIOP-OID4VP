"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.assertValidRequestObjectPayload = exports.createRequestObjectPayload = void 0;
const uuid_1 = require("uuid");
const authorization_request_1 = require("../authorization-request");
const RequestRegistration_1 = require("../authorization-request/RequestRegistration");
const helpers_1 = require("../helpers");
const types_1 = require("../types");
const Opts_1 = require("./Opts");
const createRequestObjectPayload = async (opts) => {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j;
    (0, Opts_1.assertValidRequestObjectOpts)(opts.requestObject, false);
    if (!((_a = opts.requestObject) === null || _a === void 0 ? void 0 : _a.payload)) {
        return undefined; // No request object apparently
    }
    (0, Opts_1.assertValidRequestObjectOpts)(opts.requestObject, true);
    const payload = opts.requestObject.payload;
    const state = (0, helpers_1.getState)(payload.state);
    const registration = await (0, RequestRegistration_1.createRequestRegistration)(opts.clientMetadata, opts);
    const claims = (0, authorization_request_1.createPresentationDefinitionClaimsProperties)(payload.claims);
    let clientId = payload.client_id;
    const metadataKey = opts.version >= types_1.SupportedVersion.SIOPv2_D11.valueOf() ? 'client_metadata' : 'registration';
    if (!clientId) {
        clientId = (_b = registration.payload[metadataKey]) === null || _b === void 0 ? void 0 : _b.client_id;
    }
    if (!clientId && !opts.requestObject.signature.did) {
        throw Error('Please provide a clientId for the RP');
    }
    const now = Math.round(new Date().getTime() / 1000);
    const validInSec = 120; // todo config/option
    const iat = (_c = payload.iat) !== null && _c !== void 0 ? _c : now;
    const nbf = (_d = payload.nbf) !== null && _d !== void 0 ? _d : iat;
    const exp = (_e = payload.exp) !== null && _e !== void 0 ? _e : iat + validInSec;
    const jti = (_f = payload.jti) !== null && _f !== void 0 ? _f : (0, uuid_1.v4)();
    return (0, helpers_1.removeNullUndefined)(Object.assign(Object.assign(Object.assign(Object.assign({ response_type: (_g = payload.response_type) !== null && _g !== void 0 ? _g : types_1.ResponseType.ID_TOKEN, scope: (_h = payload.scope) !== null && _h !== void 0 ? _h : types_1.Scope.OPENID, 
        //TODO implement /.well-known/openid-federation support in the OP side to resolve the client_id (URL) and retrieve the metadata
        client_id: clientId !== null && clientId !== void 0 ? clientId : opts.requestObject.signature.did, redirect_uri: payload.redirect_uri, response_mode: (_j = payload.response_mode) !== null && _j !== void 0 ? _j : types_1.ResponseMode.POST }, (payload.id_token_hint && { id_token_hint: payload.id_token_hint })), { registration_uri: registration.clientMetadataOpts.reference_uri, nonce: (0, helpers_1.getNonce)(state, payload.nonce), state }), registration.payload), { claims,
        iat,
        nbf,
        exp,
        jti }));
};
exports.createRequestObjectPayload = createRequestObjectPayload;
const assertValidRequestObjectPayload = (verPayload) => {
    if (verPayload['registration_uri'] && verPayload['registration']) {
        throw new Error(`${types_1.SIOPErrors.REG_OBJ_N_REG_URI_CANT_BE_SET_SIMULTANEOUSLY}`);
    }
};
exports.assertValidRequestObjectPayload = assertValidRequestObjectPayload;
