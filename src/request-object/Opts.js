"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.assertValidRequestObjectOpts = void 0;
const types_1 = require("../types");
const assertValidRequestObjectOpts = (opts, checkRequestObject) => {
    if (!opts) {
        throw new Error(types_1.SIOPErrors.BAD_PARAMS);
    }
    else if (opts.passBy !== types_1.PassBy.REFERENCE && opts.passBy !== types_1.PassBy.VALUE) {
        throw new Error(types_1.SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
    }
    else if (opts.passBy === types_1.PassBy.REFERENCE && !opts.reference_uri) {
        throw new Error(types_1.SIOPErrors.NO_REFERENCE_URI);
    }
    else if (!opts.payload) {
        if (opts.reference_uri) {
            // reference URI, but no actual payload to host there!
            throw Error(types_1.SIOPErrors.REFERENCE_URI_NO_PAYLOAD);
        }
        else if (checkRequestObject) {
            throw Error(types_1.SIOPErrors.BAD_PARAMS);
        }
    }
    // assertValidRequestRegistrationOpts(opts['registration'] ? opts['registration'] : opts['clientMetadata']);
};
exports.assertValidRequestObjectOpts = assertValidRequestObjectOpts;
