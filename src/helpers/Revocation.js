"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyRevocation = void 0;
const types_1 = require("../types");
const verifyRevocation = async (vpToken, revocationVerificationCallback, revocationVerification) => {
    if (!vpToken) {
        throw new Error(`VP token not provided`);
    }
    if (!revocationVerificationCallback) {
        throw new Error(`Revocation callback not provided`);
    }
    const vcs = Array.isArray(vpToken.presentation.verifiableCredential)
        ? vpToken.presentation.verifiableCredential
        : [vpToken.presentation.verifiableCredential];
    for (const vc of vcs) {
        if (revocationVerification === types_1.RevocationVerification.ALWAYS ||
            (revocationVerification === types_1.RevocationVerification.IF_PRESENT && vc.credential.credentialStatus)) {
            const result = await revocationVerificationCallback(vc.original, vc.format.toLowerCase().includes('jwt') ? types_1.VerifiableCredentialTypeFormat.JWT_VC : types_1.VerifiableCredentialTypeFormat.LDP_VC);
            if (result.status === types_1.RevocationStatus.INVALID) {
                throw new Error(`Revocation invalid for vc: ${vc.credential.id}. Error: ${result.error}`);
            }
        }
    }
};
exports.verifyRevocation = verifyRevocation;
