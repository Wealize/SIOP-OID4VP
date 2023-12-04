"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.supportedCredentialsFormats = exports.assertValidMetadata = void 0;
const types_1 = require("../types");
function assertValidMetadata(opMetadata, rpMetadata) {
    let subjectSyntaxTypesSupported = [];
    const credentials = supportedCredentialsFormats(rpMetadata.vp_formats, opMetadata.vp_formats);
    const isValidSubjectSyntax = verifySubjectSyntaxes(rpMetadata.subject_syntax_types_supported);
    if (isValidSubjectSyntax && rpMetadata.subject_syntax_types_supported) {
        subjectSyntaxTypesSupported = supportedSubjectSyntaxTypes(rpMetadata.subject_syntax_types_supported, opMetadata.subject_syntax_types_supported);
    }
    else if (isValidSubjectSyntax && (!rpMetadata.subject_syntax_types_supported || !rpMetadata.subject_syntax_types_supported.length)) {
        if (opMetadata.subject_syntax_types_supported || opMetadata.subject_syntax_types_supported.length) {
            subjectSyntaxTypesSupported = [...opMetadata.subject_syntax_types_supported];
        }
    }
    return { vp_formats: credentials, subject_syntax_types_supported: subjectSyntaxTypesSupported };
}
exports.assertValidMetadata = assertValidMetadata;
function getIntersection(rpMetadata, opMetadata) {
    let arrayA, arrayB;
    if (!Array.isArray(rpMetadata)) {
        arrayA = [rpMetadata];
    }
    else {
        arrayA = rpMetadata;
    }
    if (!Array.isArray(opMetadata)) {
        arrayB = [opMetadata];
    }
    else {
        arrayB = opMetadata;
    }
    return arrayA.filter((value) => arrayB.includes(value));
}
function verifySubjectSyntaxes(subjectSyntaxTypesSupported) {
    if (subjectSyntaxTypesSupported.length) {
        if (Array.isArray(subjectSyntaxTypesSupported)) {
            if (subjectSyntaxTypesSupported.length ===
                subjectSyntaxTypesSupported.filter((sst) => sst.includes(types_1.SubjectSyntaxTypesSupportedValues.DID.valueOf()) || sst === types_1.SubjectSyntaxTypesSupportedValues.JWK_THUMBPRINT.valueOf()).length) {
                return true;
            }
        }
    }
    return false;
}
function supportedSubjectSyntaxTypes(rpMethods, opMethods) {
    const rpMethodsList = Array.isArray(rpMethods) ? rpMethods : [rpMethods];
    const opMethodsList = Array.isArray(opMethods) ? opMethods : [opMethods];
    const supportedSubjectSyntaxTypes = getIntersection(rpMethodsList, opMethodsList);
    if (supportedSubjectSyntaxTypes.indexOf(types_1.SubjectSyntaxTypesSupportedValues.DID.valueOf()) !== -1) {
        return [types_1.SubjectSyntaxTypesSupportedValues.DID.valueOf()];
    }
    if (rpMethodsList.includes(types_1.SubjectSyntaxTypesSupportedValues.DID.valueOf())) {
        const supportedExtendedDids = opMethodsList.filter((method) => method.startsWith('did:'));
        if (supportedExtendedDids.length) {
            return supportedExtendedDids;
        }
    }
    if (opMethodsList.includes(types_1.SubjectSyntaxTypesSupportedValues.DID.valueOf())) {
        const supportedExtendedDids = rpMethodsList.filter((method) => method.startsWith('did:'));
        if (supportedExtendedDids.length) {
            return supportedExtendedDids;
        }
    }
    if (!supportedSubjectSyntaxTypes.length) {
        throw Error(types_1.SIOPErrors.DID_METHODS_NOT_SUPORTED);
    }
    const supportedDidMethods = supportedSubjectSyntaxTypes.filter((sst) => sst.includes('did:'));
    if (supportedDidMethods.length) {
        return supportedDidMethods;
    }
    return supportedSubjectSyntaxTypes;
}
function getFormatIntersection(rpFormat, opFormat) {
    const intersectionFormat = {};
    const supportedCredentials = getIntersection(Object.keys(rpFormat), Object.keys(opFormat));
    if (!supportedCredentials.length) {
        throw new Error(types_1.SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
    }
    supportedCredentials.forEach(function (crFormat) {
        const rpAlgs = [];
        const opAlgs = [];
        Object.keys(rpFormat[crFormat]).forEach((k) => rpAlgs.push(...rpFormat[crFormat][k]));
        Object.keys(opFormat[crFormat]).forEach((k) => opAlgs.push(...opFormat[crFormat][k]));
        let methodKeyRP = undefined;
        let methodKeyOP = undefined;
        Object.keys(rpFormat[crFormat]).forEach((k) => (methodKeyRP = k));
        Object.keys(opFormat[crFormat]).forEach((k) => (methodKeyOP = k));
        if (methodKeyRP !== methodKeyOP) {
            throw new Error(types_1.SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
        }
        const algs = getIntersection(rpAlgs, opAlgs);
        if (!algs.length) {
            throw new Error(types_1.SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
        }
        intersectionFormat[crFormat] = {};
        intersectionFormat[crFormat][methodKeyOP] = algs;
    });
    return intersectionFormat;
}
function supportedCredentialsFormats(rpFormat, opFormat) {
    if (!rpFormat || !opFormat || !Object.keys(rpFormat).length || !Object.keys(opFormat).length) {
        throw new Error(types_1.SIOPErrors.CREDENTIALS_FORMATS_NOT_PROVIDED);
    }
    return getFormatIntersection(rpFormat, opFormat);
}
exports.supportedCredentialsFormats = supportedCredentialsFormats;
