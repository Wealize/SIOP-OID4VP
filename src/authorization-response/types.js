"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VPTokenLocation = exports.PresentationDefinitionLocation = void 0;
var PresentationDefinitionLocation;
(function (PresentationDefinitionLocation) {
    PresentationDefinitionLocation["CLAIMS_VP_TOKEN"] = "claims.vp_token";
    PresentationDefinitionLocation["TOPLEVEL_PRESENTATION_DEF"] = "presentation_definition";
})(PresentationDefinitionLocation = exports.PresentationDefinitionLocation || (exports.PresentationDefinitionLocation = {}));
var VPTokenLocation;
(function (VPTokenLocation) {
    VPTokenLocation["AUTHORIZATION_RESPONSE"] = "authorization_response";
    VPTokenLocation["ID_TOKEN"] = "id_token";
    VPTokenLocation["TOKEN_RESPONSE"] = "token_response";
})(VPTokenLocation = exports.VPTokenLocation || (exports.VPTokenLocation = {}));
