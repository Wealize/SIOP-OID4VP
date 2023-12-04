"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mergeOAuth2AndOpenIdInRequestPayload = exports.createResponsePayload = void 0;
const id_token_1 = require("../id-token");
const request_object_1 = require("../request-object");
const types_1 = require("../types");
const OpenID4VP_1 = require("./OpenID4VP");
const Opts_1 = require("./Opts");
const createResponsePayload = async (authorizationRequest, responseOpts, idTokenPayload) => {
    (0, Opts_1.assertValidResponseOpts)(responseOpts);
    if (!authorizationRequest) {
        throw new Error(types_1.SIOPErrors.NO_REQUEST);
    }
    // If state was in request, it must be in response
    const state = await authorizationRequest.getMergedProperty('state');
    const responsePayload = Object.assign(Object.assign(Object.assign(Object.assign({}, (responseOpts.accessToken && { access_token: responseOpts.accessToken })), (responseOpts.tokenType && { token_type: responseOpts.tokenType })), (responseOpts.refreshToken && { refresh_token: responseOpts.refreshToken })), { expires_in: responseOpts.expiresIn || 3600, state });
    // vp tokens
    await (0, OpenID4VP_1.putPresentationSubmissionInLocation)(authorizationRequest, responsePayload, responseOpts, idTokenPayload);
    if (idTokenPayload) {
        responsePayload.id_token = await id_token_1.IDToken.fromIDTokenPayload(idTokenPayload, responseOpts).then((id) => id.jwt());
    }
    return responsePayload;
};
exports.createResponsePayload = createResponsePayload;
/**
 * Properties can be in oAUth2 and OpenID (JWT) style. If they are in both the OpenID prop takes precedence as they are signed.
 * @param payload
 * @param requestObject
 */
const mergeOAuth2AndOpenIdInRequestPayload = async (payload, requestObject) => {
    const payloadCopy = JSON.parse(JSON.stringify(payload));
    const requestObj = requestObject ? requestObject : await request_object_1.RequestObject.fromAuthorizationRequestPayload(payload);
    if (!requestObj) {
        return payloadCopy;
    }
    const requestObjectPayload = await requestObj.getPayload();
    return Object.assign(Object.assign({}, payloadCopy), requestObjectPayload);
};
exports.mergeOAuth2AndOpenIdInRequestPayload = mergeOAuth2AndOpenIdInRequestPayload;
