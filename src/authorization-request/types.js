"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PropertyTarget = void 0;
/**
 * Determines where a property will end up. Methods that support this argument are optional. If you do not provide any value it will default to all targets.
 */
var PropertyTarget;
(function (PropertyTarget) {
    // The property will end up in the oAuth2 authorization request
    PropertyTarget["AUTHORIZATION_REQUEST"] = "authorization-request";
    // OpenID Request Object (the JWT)
    PropertyTarget["REQUEST_OBJECT"] = "request-object";
})(PropertyTarget = exports.PropertyTarget || (exports.PropertyTarget = {}));
