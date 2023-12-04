"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mergeVerificationOpts = exports.assertValidAuthorizationRequestOpts = exports.assertValidVerifyAuthorizationRequestOpts = void 0;
const Opts_1 = require("../request-object/Opts");
const types_1 = require("../types");
const RequestRegistration_1 = require("./RequestRegistration");
const assertValidVerifyAuthorizationRequestOpts = (opts) => {
    if (!opts || !opts.verification || (!(0, types_1.isExternalVerification)(opts.verification) && !(0, types_1.isInternalVerification)(opts.verification))) {
        throw new Error(types_1.SIOPErrors.VERIFY_BAD_PARAMS);
    }
    if (!opts.correlationId) {
        throw new Error('No correlation id found');
    }
};
exports.assertValidVerifyAuthorizationRequestOpts = assertValidVerifyAuthorizationRequestOpts;
const assertValidAuthorizationRequestOpts = (opts) => {
    var _a;
    if (!opts || !opts.requestObject || (!opts.payload && !opts.requestObject.payload) || (((_a = opts.payload) === null || _a === void 0 ? void 0 : _a.request_uri) && !opts.requestObject.payload)) {
        throw new Error(types_1.SIOPErrors.BAD_PARAMS);
    }
    (0, Opts_1.assertValidRequestObjectOpts)(opts.requestObject, false);
    (0, RequestRegistration_1.assertValidRequestRegistrationOpts)(opts['registration'] ? opts['registration'] : opts.clientMetadata);
};
exports.assertValidAuthorizationRequestOpts = assertValidAuthorizationRequestOpts;
const mergeVerificationOpts = (classOpts, requestOpts) => {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t, _u, _v, _w, _x, _y, _z, _0, _1, _2, _3, _4, _5, _6, _7, _8;
    const resolver = (_c = (_b = (_a = requestOpts.verification) === null || _a === void 0 ? void 0 : _a.resolveOpts) === null || _b === void 0 ? void 0 : _b.resolver) !== null && _c !== void 0 ? _c : (_e = (_d = classOpts.verification) === null || _d === void 0 ? void 0 : _d.resolveOpts) === null || _e === void 0 ? void 0 : _e.resolver;
    const wellknownDIDVerifyCallback = (_g = (_f = requestOpts.verification) === null || _f === void 0 ? void 0 : _f.wellknownDIDVerifyCallback) !== null && _g !== void 0 ? _g : (_h = classOpts.verification) === null || _h === void 0 ? void 0 : _h.wellknownDIDVerifyCallback;
    const presentationVerificationCallback = (_k = (_j = requestOpts.verification) === null || _j === void 0 ? void 0 : _j.presentationVerificationCallback) !== null && _k !== void 0 ? _k : (_l = classOpts.verification) === null || _l === void 0 ? void 0 : _l.presentationVerificationCallback;
    const replayRegistry = (_o = (_m = requestOpts.verification) === null || _m === void 0 ? void 0 : _m.replayRegistry) !== null && _o !== void 0 ? _o : (_p = classOpts.verification) === null || _p === void 0 ? void 0 : _p.replayRegistry;
    return Object.assign(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign({}, classOpts.verification), requestOpts.verification), (wellknownDIDVerifyCallback && { wellknownDIDVerifyCallback })), (presentationVerificationCallback && { presentationVerificationCallback })), (replayRegistry && { replayRegistry })), { resolveOpts: Object.assign(Object.assign(Object.assign(Object.assign({}, (_q = classOpts.verification) === null || _q === void 0 ? void 0 : _q.resolveOpts), (_r = requestOpts.verification) === null || _r === void 0 ? void 0 : _r.resolveOpts), (resolver && { resolver })), { jwtVerifyOpts: Object.assign(Object.assign(Object.assign(Object.assign({}, (_t = (_s = classOpts.verification) === null || _s === void 0 ? void 0 : _s.resolveOpts) === null || _t === void 0 ? void 0 : _t.jwtVerifyOpts), (_v = (_u = requestOpts.verification) === null || _u === void 0 ? void 0 : _u.resolveOpts) === null || _v === void 0 ? void 0 : _v.jwtVerifyOpts), (resolver && { resolver })), { policies: Object.assign(Object.assign(Object.assign({}, (_y = (_x = (_w = classOpts.verification) === null || _w === void 0 ? void 0 : _w.resolveOpts) === null || _x === void 0 ? void 0 : _x.jwtVerifyOpts) === null || _y === void 0 ? void 0 : _y.policies), (_1 = (_0 = (_z = requestOpts.verification) === null || _z === void 0 ? void 0 : _z.resolveOpts) === null || _0 === void 0 ? void 0 : _0.jwtVerifyOpts) === null || _1 === void 0 ? void 0 : _1.policies), { aud: false }) }) }), revocationOpts: Object.assign(Object.assign(Object.assign({}, (_2 = classOpts.verification) === null || _2 === void 0 ? void 0 : _2.revocationOpts), (_3 = requestOpts.verification) === null || _3 === void 0 ? void 0 : _3.revocationOpts), { revocationVerificationCallback: (_6 = (_5 = (_4 = requestOpts.verification) === null || _4 === void 0 ? void 0 : _4.revocationOpts) === null || _5 === void 0 ? void 0 : _5.revocationVerificationCallback) !== null && _6 !== void 0 ? _6 : (_8 = (_7 = classOpts === null || classOpts === void 0 ? void 0 : classOpts.verification) === null || _7 === void 0 ? void 0 : _7.revocationOpts) === null || _8 === void 0 ? void 0 : _8.revocationVerificationCallback }) });
};
exports.mergeVerificationOpts = mergeVerificationOpts;
