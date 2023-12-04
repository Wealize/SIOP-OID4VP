"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RequestObject = void 0;
const did_jwt_1 = require("did-jwt");
const Opts_1 = require("../authorization-request/Opts");
const did_1 = require("../did");
const helpers_1 = require("../helpers");
const types_1 = require("../types");
const Opts_2 = require("./Opts");
const Payload_1 = require("./Payload");
class RequestObject {
    constructor(opts, payload, jwt) {
        this.opts = opts ? RequestObject.mergeOAuth2AndOpenIdProperties(opts) : undefined;
        this.payload = payload;
        this.jwt = jwt;
    }
    /**
     * Create a request object that typically is used as a JWT on RP side, typically this method is called automatically when creating an Authorization Request, but you could use it directly!
     *
     * @param authorizationRequestOpts Request Object options to build a Request Object
     * @remarks This method is used to generate a SIOP request Object.
     * First it generates the request object payload, and then it a signed JWT can be accessed on request.
     *
     * Normally you will want to use the Authorization Request class. That class creates a URI that includes the JWT from this class in the URI
     * If you do use this class directly, you can call the `convertRequestObjectToURI` afterwards to get the URI.
     * Please note that the Authorization Request allows you to differentiate between OAuth2 and OpenID parameters that become
     * part of the URI and which become part of the Request Object. If you generate a URI based upon the result of this class,
     * the URI will be constructed based on the Request Object only!
     */
    static async fromOpts(authorizationRequestOpts) {
        (0, Opts_1.assertValidAuthorizationRequestOpts)(authorizationRequestOpts);
        const signature = authorizationRequestOpts.requestObject.signature; // We copy the signature separately as it can contain a function, which would be removed in the merge function below
        const requestObjectOpts = RequestObject.mergeOAuth2AndOpenIdProperties(authorizationRequestOpts);
        const mergedOpts = Object.assign(Object.assign({}, authorizationRequestOpts), { requestObject: Object.assign(Object.assign(Object.assign({}, authorizationRequestOpts.requestObject), requestObjectOpts), { signature }) });
        return new RequestObject(mergedOpts, await (0, Payload_1.createRequestObjectPayload)(mergedOpts));
    }
    static async fromJwt(requestObjectJwt) {
        return new RequestObject(undefined, undefined, requestObjectJwt);
    }
    static async fromPayload(requestObjectPayload, authorizationRequestOpts) {
        return new RequestObject(authorizationRequestOpts, requestObjectPayload);
    }
    static async fromAuthorizationRequestPayload(payload) {
        const requestObjectJwt = payload.request || payload.request_uri ? await (0, helpers_1.fetchByReferenceOrUseByValue)(payload.request_uri, payload.request, true) : undefined;
        return requestObjectJwt ? await RequestObject.fromJwt(requestObjectJwt) : undefined;
    }
    async toJwt() {
        if (!this.jwt) {
            if (!this.opts) {
                throw Error(types_1.SIOPErrors.BAD_PARAMS);
            }
            else if (!this.payload) {
                return undefined;
            }
            this.removeRequestProperties();
            if (this.payload.registration_uri) {
                delete this.payload.registration;
            }
            (0, Payload_1.assertValidRequestObjectPayload)(this.payload);
            this.jwt = await (0, did_1.signRequestObjectPayload)(this.payload, this.opts);
        }
        return this.jwt;
    }
    async getPayload() {
        if (!this.payload) {
            if (!this.jwt) {
                return undefined;
            }
            this.payload = (0, helpers_1.removeNullUndefined)((0, did_jwt_1.decodeJWT)(this.jwt).payload);
            this.removeRequestProperties();
            if (this.payload.registration_uri) {
                delete this.payload.registration;
            }
            else if (this.payload.registration) {
                delete this.payload.registration_uri;
            }
        }
        (0, Payload_1.assertValidRequestObjectPayload)(this.payload);
        return this.payload;
    }
    async assertValid() {
        if (this.options) {
            (0, Opts_2.assertValidRequestObjectOpts)(this.options, false);
        }
        (0, Payload_1.assertValidRequestObjectPayload)(await this.getPayload());
    }
    get options() {
        return this.opts;
    }
    removeRequestProperties() {
        if (this.payload) {
            // https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
            // request and request_uri parameters MUST NOT be included in Request Objects.
            delete this.payload.request;
            delete this.payload.request_uri;
        }
    }
    static mergeOAuth2AndOpenIdProperties(opts) {
        var _a, _b, _c;
        if (!opts) {
            throw Error(types_1.SIOPErrors.BAD_PARAMS);
        }
        const isAuthReq = opts['requestObject'] !== undefined;
        const mergedOpts = JSON.parse(JSON.stringify(opts));
        const signature = (_b = (_a = opts['requestObject']) === null || _a === void 0 ? void 0 : _a.signature) === null || _b === void 0 ? void 0 : _b.signature;
        if (signature && mergedOpts.requestObject.signature) {
            mergedOpts.requestObject.signature.signature = signature;
        }
        (_c = mergedOpts === null || mergedOpts === void 0 ? void 0 : mergedOpts.request) === null || _c === void 0 ? true : delete _c.requestObject;
        return isAuthReq ? mergedOpts.requestObject : mergedOpts;
    }
}
exports.RequestObject = RequestObject;
