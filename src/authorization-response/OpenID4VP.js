"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.assertValidVerifiablePresentations = exports.putPresentationSubmissionInLocation = exports.createPresentationSubmission = exports.extractPresentationsFromAuthorizationResponse = exports.verifyPresentations = void 0;
const ssi_types_1 = require("@sphereon/ssi-types");
const helpers_1 = require("../helpers");
const types_1 = require("../types");
const PresentationExchange_1 = require("./PresentationExchange");
const types_2 = require("./types");
const verifyPresentations = async (authorizationResponse, verifyOpts) => {
    var _a, _b, _c;
    const presentations = await (0, exports.extractPresentationsFromAuthorizationResponse)(authorizationResponse);
    const presentationDefinitions = verifyOpts.presentationDefinitions
        ? Array.isArray(verifyOpts.presentationDefinitions)
            ? verifyOpts.presentationDefinitions
            : [verifyOpts.presentationDefinitions]
        : [];
    let idPayload;
    if (authorizationResponse.idToken) {
        idPayload = await authorizationResponse.idToken.payload();
    }
    // todo: Probably wise to check against request for the location of the submission_data
    const presentationSubmission = authorizationResponse.payload.presentation_submission
        ? authorizationResponse.payload.presentation_submission
        : (_a = idPayload === null || idPayload === void 0 ? void 0 : idPayload._vp_token) === null || _a === void 0 ? void 0 : _a.presentation_submission;
    await (0, exports.assertValidVerifiablePresentations)({
        presentationDefinitions,
        presentations,
        verificationCallback: verifyOpts.verification.presentationVerificationCallback,
        opts: {
            presentationSubmission,
            restrictToFormats: verifyOpts.restrictToFormats,
            restrictToDIDMethods: verifyOpts.restrictToDIDMethods,
        },
    });
    const revocationVerification = ((_b = verifyOpts.verification) === null || _b === void 0 ? void 0 : _b.revocationOpts)
        ? verifyOpts.verification.revocationOpts.revocationVerification
        : types_1.RevocationVerification.IF_PRESENT;
    if (revocationVerification !== types_1.RevocationVerification.NEVER) {
        if (!((_c = verifyOpts.verification.revocationOpts) === null || _c === void 0 ? void 0 : _c.revocationVerificationCallback)) {
            throw Error(`Please provide a revocation callback as revocation checking of credentials and presentations is not disabled`);
        }
        for (const vp of presentations) {
            await (0, helpers_1.verifyRevocation)(vp, verifyOpts.verification.revocationOpts.revocationVerificationCallback, revocationVerification);
        }
    }
    return { presentations, presentationDefinitions, submissionData: presentationSubmission };
};
exports.verifyPresentations = verifyPresentations;
const extractPresentationsFromAuthorizationResponse = async (response) => {
    const wrappedVerifiablePresentations = [];
    if (response.payload.vp_token) {
        const presentations = Array.isArray(response.payload.vp_token) ? response.payload.vp_token : [response.payload.vp_token];
        for (const presentation of presentations) {
            wrappedVerifiablePresentations.push(ssi_types_1.CredentialMapper.toWrappedVerifiablePresentation(presentation));
        }
    }
    return wrappedVerifiablePresentations;
};
exports.extractPresentationsFromAuthorizationResponse = extractPresentationsFromAuthorizationResponse;
const createPresentationSubmission = async (verifiablePresentations) => {
    let submission_data;
    for (const verifiablePresentation of verifiablePresentations) {
        const wrappedPresentation = ssi_types_1.CredentialMapper.toWrappedVerifiablePresentation(verifiablePresentation);
        const submission = wrappedPresentation.presentation.presentation_submission ||
            wrappedPresentation.decoded.presentation_submission ||
            (typeof wrappedPresentation.original !== 'string' && wrappedPresentation.original.presentation_submission);
        if (!submission) {
            // todo in the future PEX might supply the submission_data separately as well
            throw Error('Verifiable Presentation has no submission_data');
        }
        if (!submission_data) {
            submission_data = submission;
        }
        else {
            // We are pushing multiple descriptors into one submission_data, as it seems this is something which is assumed in OpenID4VP, but not supported in Presentation Exchange (a single VP always has a single submission_data)
            Array.isArray(submission_data.descriptor_map)
                ? submission_data.descriptor_map.push(...submission.descriptor_map)
                : (submission_data.descriptor_map = [...submission.descriptor_map]);
        }
    }
    return submission_data;
};
exports.createPresentationSubmission = createPresentationSubmission;
const putPresentationSubmissionInLocation = async (authorizationRequest, responsePayload, resOpts, idTokenPayload) => {
    var _a, _b, _c, _d, _e, _f;
    const version = await authorizationRequest.getSupportedVersion();
    const idTokenType = await authorizationRequest.containsResponseType(types_1.ResponseType.ID_TOKEN);
    const authResponseType = await authorizationRequest.containsResponseType(types_1.ResponseType.VP_TOKEN);
    // const requestPayload = await authorizationRequest.mergedPayloads();
    if (!resOpts.presentationExchange) {
        return;
    }
    else if (resOpts.presentationExchange.verifiablePresentations.length === 0) {
        throw Error('Presentation Exchange options set, but no verifiable presentations provided');
    }
    const submissionData = (_a = resOpts.presentationExchange.presentationSubmission) !== null && _a !== void 0 ? _a : (await (0, exports.createPresentationSubmission)(resOpts.presentationExchange.verifiablePresentations));
    const location = (_c = (_b = resOpts.presentationExchange) === null || _b === void 0 ? void 0 : _b.vpTokenLocation) !== null && _c !== void 0 ? _c : (idTokenType ? types_2.VPTokenLocation.ID_TOKEN : types_2.VPTokenLocation.AUTHORIZATION_RESPONSE);
    switch (location) {
        case types_2.VPTokenLocation.TOKEN_RESPONSE: {
            throw Error('Token response for VP token is not supported yet');
        }
        case types_2.VPTokenLocation.ID_TOKEN: {
            if (!idTokenPayload) {
                throw Error('Cannot place submission data _vp_token in id token if no id token is present');
            }
            else if (version >= types_1.SupportedVersion.SIOPv2_D11) {
                throw Error(`This version of the OpenID4VP spec does not allow to store the vp submission data in the ID token`);
            }
            else if (!idTokenType) {
                throw Error(`Cannot place vp token in ID token as the RP didn't provide an "openid" scope in the request`);
            }
            if ((_d = idTokenPayload._vp_token) === null || _d === void 0 ? void 0 : _d.presentation_submission) {
                if (submissionData !== idTokenPayload._vp_token.presentation_submission) {
                    throw Error('Different submission data was provided as an option, but exising submission data was already present in the id token');
                }
            }
            else {
                if (!idTokenPayload._vp_token) {
                    idTokenPayload._vp_token = { presentation_submission: submissionData };
                }
                else {
                    idTokenPayload._vp_token.presentation_submission = submissionData;
                }
            }
            break;
        }
        case types_2.VPTokenLocation.AUTHORIZATION_RESPONSE: {
            if (!authResponseType) {
                throw Error('Cannot place vp token in Authorization Response as there is no vp_token scope in the auth request');
            }
            if (responsePayload.presentation_submission) {
                if (submissionData !== responsePayload.presentation_submission) {
                    throw Error('Different submission data was provided as an option, but exising submission data was already present in the authorization response');
                }
            }
            else {
                responsePayload.presentation_submission = submissionData;
            }
        }
    }
    const vps = ((_f = (_e = resOpts.presentationExchange) === null || _e === void 0 ? void 0 : _e.verifiablePresentations) === null || _f === void 0 ? void 0 : _f.map((vp) => ssi_types_1.CredentialMapper.toWrappedVerifiablePresentation(vp).original)) || [];
    responsePayload.vp_token = vps.length === 1 ? vps[0] : vps;
};
exports.putPresentationSubmissionInLocation = putPresentationSubmissionInLocation;
const assertValidVerifiablePresentations = async (args) => {
    if ((!args.presentationDefinitions || args.presentationDefinitions.filter((a) => a.definition).length === 0) &&
        (!args.presentations || (Array.isArray(args.presentations) && args.presentations.filter((vp) => vp.presentation).length === 0))) {
        return;
    }
    PresentationExchange_1.PresentationExchange.assertValidPresentationDefinitionWithLocations(args.presentationDefinitions);
    const presentationsWithFormat = args.presentations;
    if (args.presentationDefinitions && args.presentationDefinitions.length && (!presentationsWithFormat || presentationsWithFormat.length === 0)) {
        throw new Error(types_1.SIOPErrors.AUTH_REQUEST_EXPECTS_VP);
    }
    else if ((!args.presentationDefinitions || args.presentationDefinitions.length === 0) &&
        presentationsWithFormat &&
        presentationsWithFormat.length > 0) {
        throw new Error(types_1.SIOPErrors.AUTH_REQUEST_DOESNT_EXPECT_VP);
    }
    else if (args.presentationDefinitions && presentationsWithFormat && args.presentationDefinitions.length != presentationsWithFormat.length) {
        throw new Error(types_1.SIOPErrors.AUTH_REQUEST_EXPECTS_VP);
    }
    else if (args.presentationDefinitions && presentationsWithFormat) {
        await PresentationExchange_1.PresentationExchange.validatePresentationsAgainstDefinitions(args.presentationDefinitions, presentationsWithFormat, args.verificationCallback, args.opts);
    }
};
exports.assertValidVerifiablePresentations = assertValidVerifiablePresentations;
