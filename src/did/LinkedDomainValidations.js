"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateLinkedDomainWithDid = void 0;
const wellknown_dids_client_1 = require("@sphereon/wellknown-dids-client");
const types_1 = require("../types");
const DIDResolution_1 = require("./DIDResolution");
const DidJWT_1 = require("./DidJWT");
function getValidationErrorMessages(validationResult) {
    const messages = [];
    if (validationResult.message) {
        messages.push(validationResult.message);
    }
    if (validationResult === null || validationResult === void 0 ? void 0 : validationResult.endpointDescriptors.length) {
        for (const endpointDescriptor of validationResult.endpointDescriptors) {
            if (endpointDescriptor.message) {
                messages.push(endpointDescriptor.message);
            }
            if (endpointDescriptor.resources) {
                for (const resource of endpointDescriptor.resources) {
                    if (resource.message) {
                        messages.push(resource.message);
                    }
                }
            }
        }
    }
    return messages;
}
/**
 * @param validationErrorMessages
 * @return returns false if the messages received from wellknown-dids-client makes this invalid for CheckLinkedDomain.IF_PRESENT plus the message itself
 *                  and true for when we can move on
 */
function checkInvalidMessages(validationErrorMessages) {
    if (!validationErrorMessages || !validationErrorMessages.length) {
        return { status: false, message: 'linked domain is invalid.' };
    }
    const validMessages = [
        wellknown_dids_client_1.WDCErrors.PROPERTY_LINKED_DIDS_DOES_NOT_CONTAIN_ANY_DOMAIN_LINK_CREDENTIALS.valueOf(),
        wellknown_dids_client_1.WDCErrors.PROPERTY_LINKED_DIDS_NOT_PRESENT.valueOf(),
        wellknown_dids_client_1.WDCErrors.PROPERTY_TYPE_NOT_CONTAIN_VALID_LINKED_DOMAIN.valueOf(),
        wellknown_dids_client_1.WDCErrors.PROPERTY_SERVICE_NOT_PRESENT.valueOf(),
    ];
    for (const validationErrorMessage of validationErrorMessages) {
        if (!validMessages.filter((vm) => validationErrorMessage.includes(vm)).pop()) {
            return { status: false, message: validationErrorMessage };
        }
    }
    return { status: true };
}
async function validateLinkedDomainWithDid(did, verification) {
    const { checkLinkedDomain, resolveOpts, wellknownDIDVerifyCallback } = verification;
    if (checkLinkedDomain === types_1.CheckLinkedDomain.NEVER) {
        return;
    }
    const didDocument = await (0, DIDResolution_1.resolveDidDocument)(did, Object.assign(Object.assign({}, resolveOpts), { subjectSyntaxTypesSupported: [(0, DidJWT_1.toSIOPRegistrationDidMethod)((0, DidJWT_1.getMethodFromDid)(did))] }));
    if (!didDocument) {
        throw Error(`Could not resolve DID: ${did}`);
    }
    if ((!didDocument.service || !didDocument.service.find((s) => s.type === 'LinkedDomains')) && checkLinkedDomain === types_1.CheckLinkedDomain.IF_PRESENT) {
        // No linked domains in DID document and it was optional. Let's cut it short here.
        return;
    }
    try {
        const validationResult = await checkWellKnownDid({ didDocument, verifyCallback: wellknownDIDVerifyCallback });
        if (validationResult.status === wellknown_dids_client_1.ValidationStatusEnum.INVALID) {
            const validationErrorMessages = getValidationErrorMessages(validationResult);
            const messageCondition = checkInvalidMessages(validationErrorMessages);
            if (checkLinkedDomain === types_1.CheckLinkedDomain.ALWAYS || (checkLinkedDomain === types_1.CheckLinkedDomain.IF_PRESENT && !messageCondition.status)) {
                throw new Error(messageCondition.message ? messageCondition.message : validationErrorMessages[0]);
            }
        }
    }
    catch (err) {
        const messageCondition = checkInvalidMessages([err.message]);
        if (checkLinkedDomain === types_1.CheckLinkedDomain.ALWAYS || (checkLinkedDomain === types_1.CheckLinkedDomain.IF_PRESENT && !messageCondition.status)) {
            throw new Error(err.message);
        }
    }
}
exports.validateLinkedDomainWithDid = validateLinkedDomainWithDid;
async function checkWellKnownDid(args) {
    const verifier = new wellknown_dids_client_1.WellKnownDidVerifier({
        verifySignatureCallback: args.verifyCallback,
        onlyVerifyServiceDid: false,
    });
    return await verifier.verifyDomainLinkage({ didDocument: args.didDocument });
}
