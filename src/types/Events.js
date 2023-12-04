"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthorizationEvent = exports.AuthorizationEvents = void 0;
var AuthorizationEvents;
(function (AuthorizationEvents) {
    AuthorizationEvents["ON_AUTH_REQUEST_CREATED_SUCCESS"] = "onAuthRequestCreatedSuccess";
    AuthorizationEvents["ON_AUTH_REQUEST_CREATED_FAILED"] = "onAuthRequestCreatedFailed";
    AuthorizationEvents["ON_AUTH_REQUEST_SENT_SUCCESS"] = "onAuthRequestSentSuccess";
    AuthorizationEvents["ON_AUTH_REQUEST_SENT_FAILED"] = "onAuthRequestSentFailed";
    AuthorizationEvents["ON_AUTH_REQUEST_RECEIVED_SUCCESS"] = "onAuthRequestReceivedSuccess";
    AuthorizationEvents["ON_AUTH_REQUEST_RECEIVED_FAILED"] = "onAuthRequestReceivedFailed";
    AuthorizationEvents["ON_AUTH_REQUEST_VERIFIED_SUCCESS"] = "onAuthRequestVerifiedSuccess";
    AuthorizationEvents["ON_AUTH_REQUEST_VERIFIED_FAILED"] = "onAuthRequestVerifiedFailed";
    AuthorizationEvents["ON_AUTH_RESPONSE_CREATE_SUCCESS"] = "onAuthResponseSentSuccess";
    AuthorizationEvents["ON_AUTH_RESPONSE_CREATE_FAILED"] = "onAuthResponseSentFailed";
    AuthorizationEvents["ON_AUTH_RESPONSE_SENT_SUCCESS"] = "onAuthResponseSentSuccess";
    AuthorizationEvents["ON_AUTH_RESPONSE_SENT_FAILED"] = "onAuthResponseSentFailed";
    AuthorizationEvents["ON_AUTH_RESPONSE_RECEIVED_SUCCESS"] = "onAuthResponseReceivedSuccess";
    AuthorizationEvents["ON_AUTH_RESPONSE_RECEIVED_FAILED"] = "onAuthResponseReceivedFailed";
    AuthorizationEvents["ON_AUTH_RESPONSE_VERIFIED_SUCCESS"] = "onAuthResponseVerifiedSuccess";
    AuthorizationEvents["ON_AUTH_RESPONSE_VERIFIED_FAILED"] = "onAuthResponseReceivedFailed";
})(AuthorizationEvents = exports.AuthorizationEvents || (exports.AuthorizationEvents = {}));
class AuthorizationEvent {
    constructor(args) {
        //fixme: Create correlationId if not provided. Might need to be deferred to registry though
        this._correlationId = args.correlationId;
        this._timestamp = Date.now();
        this._subject = args.subject;
        this._error = args.error;
    }
    get subject() {
        return this._subject;
    }
    get timestamp() {
        return this._timestamp;
    }
    get error() {
        return this._error;
    }
    hasError() {
        return !!this._error;
    }
    get correlationId() {
        return this._correlationId;
    }
}
exports.AuthorizationEvent = AuthorizationEvent;
