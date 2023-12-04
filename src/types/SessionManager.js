"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthorizationResponseStateStatus = exports.AuthorizationRequestStateStatus = void 0;
var AuthorizationRequestStateStatus;
(function (AuthorizationRequestStateStatus) {
    AuthorizationRequestStateStatus["CREATED"] = "created";
    AuthorizationRequestStateStatus["SENT"] = "sent";
    AuthorizationRequestStateStatus["RECEIVED"] = "received";
    AuthorizationRequestStateStatus["VERIFIED"] = "verified";
    AuthorizationRequestStateStatus["ERROR"] = "error";
})(AuthorizationRequestStateStatus = exports.AuthorizationRequestStateStatus || (exports.AuthorizationRequestStateStatus = {}));
var AuthorizationResponseStateStatus;
(function (AuthorizationResponseStateStatus) {
    AuthorizationResponseStateStatus["CREATED"] = "created";
    AuthorizationResponseStateStatus["SENT"] = "sent";
    AuthorizationResponseStateStatus["RECEIVED"] = "received";
    AuthorizationResponseStateStatus["VERIFIED"] = "verified";
    AuthorizationResponseStateStatus["ERROR"] = "error";
})(AuthorizationResponseStateStatus = exports.AuthorizationResponseStateStatus || (exports.AuthorizationResponseStateStatus = {}));
