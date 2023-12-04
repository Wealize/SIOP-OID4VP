"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.URI = void 0;
const did_jwt_1 = require("did-jwt");
const PresentationExchange_1 = require("../authorization-response/PresentationExchange");
const helpers_1 = require("../helpers");
const request_object_1 = require("../request-object");
const types_1 = require("../types");
const AuthorizationRequest_1 = require("./AuthorizationRequest");
const Payload_1 = require("./Payload");
class URI {
    constructor({ scheme, encodedUri, encodingFormat, authorizationRequestPayload, requestObjectJwt }) {
        this._scheme = scheme;
        this._encodedUri = encodedUri;
        this._encodingFormat = encodingFormat;
        this._authorizationRequestPayload = authorizationRequestPayload;
        this._requestObjectJwt = requestObjectJwt;
    }
    static async fromUri(uri) {
        if (!uri) {
            throw Error(types_1.SIOPErrors.BAD_PARAMS);
        }
        const { scheme, requestObjectJwt, authorizationRequestPayload, registrationMetadata } = await URI.parseAndResolve(uri);
        const requestObjectPayload = requestObjectJwt ? (0, did_jwt_1.decodeJWT)(requestObjectJwt).payload : undefined;
        if (requestObjectPayload) {
            (0, request_object_1.assertValidRequestObjectPayload)(requestObjectPayload);
        }
        const result = new URI({
            scheme,
            encodingFormat: types_1.UrlEncodingFormat.FORM_URL_ENCODED,
            encodedUri: uri,
            authorizationRequestPayload,
            requestObjectJwt,
        });
        result._registrationMetadataPayload = registrationMetadata;
        return result;
    }
    /**
     * Create a signed URL encoded URI with a signed SIOP request token on RP side
     *
     * @param opts Request input data to build a  SIOP Request Token
     * @remarks This method is used to generate a SIOP request with info provided by the RP.
     * First it generates the request payload and then it creates the signed JWT, which is returned as a URI
     *
     * Normally you will want to use this method to create the request.
     */
    static async fromOpts(opts) {
        if (!opts) {
            throw Error(types_1.SIOPErrors.BAD_PARAMS);
        }
        const authorizationRequest = await AuthorizationRequest_1.AuthorizationRequest.fromOpts(opts);
        return await URI.fromAuthorizationRequest(authorizationRequest);
    }
    async toAuthorizationRequest() {
        return await AuthorizationRequest_1.AuthorizationRequest.fromUriOrJwt(this);
    }
    get requestObjectBy() {
        if (!this.requestObjectJwt) {
            return { passBy: types_1.PassBy.NONE };
        }
        if (this.authorizationRequestPayload.request_uri) {
            return { passBy: types_1.PassBy.REFERENCE, reference_uri: this.authorizationRequestPayload.request_uri };
        }
        return { passBy: types_1.PassBy.VALUE };
    }
    get metadataObjectBy() {
        if (!this.authorizationRequestPayload.registration_uri && !this.authorizationRequestPayload.registration) {
            return { passBy: types_1.PassBy.NONE };
        }
        if (this.authorizationRequestPayload.registration_uri) {
            return { passBy: types_1.PassBy.REFERENCE, reference_uri: this.authorizationRequestPayload.registration_uri };
        }
        return { passBy: types_1.PassBy.VALUE };
    }
    /**
     * Create a URI from the request object, typically you will want to use the createURI version!
     *
     * @remarks This method is used to generate a SIOP request Object with info provided by the RP.
     * First it generates the request object payload, and then it creates the signed JWT.
     *
     * Please note that the createURI method allows you to differentiate between OAuth2 and OpenID parameters that become
     * part of the URI and which become part of the Request Object. If you generate a URI based upon the result of this method,
     * the URI will be constructed based on the Request Object only!
     */
    static async fromRequestObject(requestObject) {
        if (!requestObject) {
            throw Error(types_1.SIOPErrors.BAD_PARAMS);
        }
        return await URI.fromAuthorizationRequestPayload(requestObject.options, await AuthorizationRequest_1.AuthorizationRequest.fromUriOrJwt(await requestObject.toJwt()));
    }
    static async fromAuthorizationRequest(authorizationRequest) {
        if (!authorizationRequest) {
            throw Error(types_1.SIOPErrors.BAD_PARAMS);
        }
        return await URI.fromAuthorizationRequestPayload(Object.assign(Object.assign({}, authorizationRequest.options.requestObject), { version: authorizationRequest.options.version, uriScheme: authorizationRequest.options.uriScheme }), authorizationRequest.payload, authorizationRequest.requestObject);
    }
    /**
     * Creates an URI Request
     * @param opts Options to define the Uri Request
     * @param authorizationRequestPayload
     *
     */
    static async fromAuthorizationRequestPayload(opts, authorizationRequestPayload, requestObject) {
        if (!authorizationRequestPayload) {
            if (!requestObject || !(await requestObject.getPayload())) {
                throw Error(types_1.SIOPErrors.BAD_PARAMS);
            }
            authorizationRequestPayload = {}; // No auth request payload, so the eventual URI will contain a `request_uri` or `request` value only
        }
        const isJwt = typeof authorizationRequestPayload === 'string';
        const requestObjectJwt = requestObject
            ? await requestObject.toJwt()
            : typeof authorizationRequestPayload === 'string'
                ? authorizationRequestPayload
                : authorizationRequestPayload.request;
        if (isJwt && (!requestObjectJwt || !requestObjectJwt.startsWith('ey'))) {
            throw Error(types_1.SIOPErrors.NO_JWT);
        }
        const requestObjectPayload = requestObjectJwt ? (0, did_jwt_1.decodeJWT)(requestObjectJwt).payload : undefined;
        if (requestObjectPayload) {
            // Only used to validate if the request object contains presentation definition(s)
            await PresentationExchange_1.PresentationExchange.findValidPresentationDefinitions(Object.assign(Object.assign({}, authorizationRequestPayload), requestObjectPayload));
            (0, request_object_1.assertValidRequestObjectPayload)(requestObjectPayload);
            if (requestObjectPayload.registration) {
                (0, Payload_1.assertValidRPRegistrationMedataPayload)(requestObjectPayload.registration);
            }
        }
        const uniformAuthorizationRequestPayload = typeof authorizationRequestPayload === 'string' ? requestObjectPayload : authorizationRequestPayload;
        if (!uniformAuthorizationRequestPayload) {
            throw Error(types_1.SIOPErrors.BAD_PARAMS);
        }
        const type = opts.passBy;
        if (!type) {
            throw new Error(types_1.SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
        }
        const authorizationRequest = await AuthorizationRequest_1.AuthorizationRequest.fromUriOrJwt(requestObjectJwt);
        let scheme;
        if (opts.uriScheme) {
            scheme = opts.uriScheme.endsWith('://') ? opts.uriScheme : `${opts.uriScheme}://`;
        }
        else if (opts.version) {
            if (opts.version === types_1.SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1) {
                scheme = 'openid-vc://';
            }
            else {
                scheme = 'openid://';
            }
        }
        else {
            try {
                scheme =
                    (await authorizationRequest.getSupportedVersion()) === types_1.SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1 ? 'openid-vc://' : 'openid://';
            }
            catch (error) {
                scheme = 'openid://';
            }
        }
        if (type === types_1.PassBy.REFERENCE) {
            if (!opts.reference_uri) {
                throw new Error(types_1.SIOPErrors.NO_REFERENCE_URI);
            }
            uniformAuthorizationRequestPayload.request_uri = opts.reference_uri;
            delete uniformAuthorizationRequestPayload.request;
        }
        else if (type === types_1.PassBy.VALUE) {
            uniformAuthorizationRequestPayload.request = requestObjectJwt;
            delete uniformAuthorizationRequestPayload.request_uri;
        }
        return new URI({
            scheme,
            encodedUri: `${scheme}?${(0, helpers_1.encodeJsonAsURI)(uniformAuthorizationRequestPayload)}`,
            encodingFormat: types_1.UrlEncodingFormat.FORM_URL_ENCODED,
            // requestObjectBy: opts.requestBy,
            authorizationRequestPayload: uniformAuthorizationRequestPayload,
            requestObjectJwt: requestObjectJwt,
        });
    }
    /**
     * Create a Authentication Request Payload from a URI string
     *
     * @param uri
     */
    static parse(uri) {
        if (!uri) {
            throw Error(types_1.SIOPErrors.BAD_PARAMS);
        }
        // We strip the uri scheme before passing it to the decode function
        const scheme = uri.match(/^([a-zA-Z][a-zA-Z0-9-_]*:\/\/)/g)[0];
        const authorizationRequestPayload = (0, helpers_1.decodeUriAsJson)(uri);
        return { scheme, authorizationRequestPayload };
    }
    static async parseAndResolve(uri) {
        var _a, _b;
        if (!uri) {
            throw Error(types_1.SIOPErrors.BAD_PARAMS);
        }
        const { authorizationRequestPayload, scheme } = this.parse(uri);
        const requestObjectJwt = await (0, helpers_1.fetchByReferenceOrUseByValue)(authorizationRequestPayload.request_uri, authorizationRequestPayload.request, true);
        const registrationMetadata = await (0, helpers_1.fetchByReferenceOrUseByValue)((_a = authorizationRequestPayload['client_metadata_uri']) !== null && _a !== void 0 ? _a : authorizationRequestPayload['registration_uri'], (_b = authorizationRequestPayload['client_metadata']) !== null && _b !== void 0 ? _b : authorizationRequestPayload['registration']);
        (0, Payload_1.assertValidRPRegistrationMedataPayload)(registrationMetadata);
        return { scheme, authorizationRequestPayload, requestObjectJwt, registrationMetadata };
    }
    get encodingFormat() {
        return this._encodingFormat;
    }
    get encodedUri() {
        return this._encodedUri;
    }
    get authorizationRequestPayload() {
        return this._authorizationRequestPayload;
    }
    get requestObjectJwt() {
        return this._requestObjectJwt;
    }
    get scheme() {
        return this._scheme;
    }
    get registrationMetadataPayload() {
        return this._registrationMetadataPayload;
    }
}
exports.URI = URI;
