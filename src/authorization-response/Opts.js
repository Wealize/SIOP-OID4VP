"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.assertValidVerifyOpts = exports.assertValidResponseOpts = void 0;
const types_1 = require("../types");
const assertValidResponseOpts = (opts) => {
    if (!opts /*|| !opts.redirectUri*/ || !opts.signature /*|| !opts.nonce*/ /* || !opts.did*/) {
        throw new Error(types_1.SIOPErrors.BAD_PARAMS);
    }
    else if (!((0, types_1.isInternalSignature)(opts.signature) || (0, types_1.isExternalSignature)(opts.signature) || (0, types_1.isSuppliedSignature)(opts.signature))) {
        throw new Error(types_1.SIOPErrors.SIGNATURE_OBJECT_TYPE_NOT_SET);
    }
};
exports.assertValidResponseOpts = assertValidResponseOpts;
const assertValidVerifyOpts = (opts) => {
    if (!opts || !opts.verification || (!(0, types_1.isExternalVerification)(opts.verification) && !(0, types_1.isInternalVerification)(opts.verification))) {
        throw new Error(types_1.SIOPErrors.VERIFY_BAD_PARAMS);
    }
};
exports.assertValidVerifyOpts = assertValidVerifyOpts;
