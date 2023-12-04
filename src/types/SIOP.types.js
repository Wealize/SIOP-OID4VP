"use strict";
// noinspection JSUnusedGlobalSymbols
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContentType = exports.SupportedVersion = exports.RevocationVerification = exports.RevocationStatus = exports.isPresentation = exports.isVP = exports.isExternalVerification = exports.isInternalVerification = exports.isResponsePayload = exports.isRequestPayload = exports.isResponseOpts = exports.isRequestOpts = exports.isNoSignature = exports.isSuppliedSignature = exports.isExternalSignature = exports.isInternalSignature = exports.ResponseIss = exports.Schema = exports.SubjectType = exports.CredentialFormat = exports.SubjectSyntaxTypesSupportedValues = exports.SubjectIdentifierType = exports.ResponseType = exports.Scope = exports.SigningAlgo = exports.TokenEndpointAuthMethod = exports.KeyCurve = exports.KeyType = exports.UrlEncodingFormat = exports.ProtocolFlow = exports.ResponseMode = exports.GrantType = exports.VerificationMode = exports.CheckLinkedDomain = exports.ResponseContext = exports.PassBy = exports.EncKeyAlgorithm = exports.EncSymmetricAlgorithmCode = exports.VerifiableCredentialTypeFormat = exports.VerifiablePresentationTypeFormat = exports.IdTokenType = exports.ClaimType = exports.AuthenticationContextReferences = exports.DEFAULT_EXPIRATION_TIME = void 0;
exports.DEFAULT_EXPIRATION_TIME = 10 * 60;
var AuthenticationContextReferences;
(function (AuthenticationContextReferences) {
    AuthenticationContextReferences["PHR"] = "phr";
    AuthenticationContextReferences["PHRH"] = "phrh";
})(AuthenticationContextReferences = exports.AuthenticationContextReferences || (exports.AuthenticationContextReferences = {}));
var ClaimType;
(function (ClaimType) {
    ClaimType["NORMAL"] = "normal";
    ClaimType["AGGREGATED"] = "aggregated";
    ClaimType["DISTRIBUTED"] = "distributed";
})(ClaimType = exports.ClaimType || (exports.ClaimType = {}));
var IdTokenType;
(function (IdTokenType) {
    IdTokenType["SUBJECT_SIGNED"] = "subject_signed";
    IdTokenType["ATTESTER_SIGNED"] = "attester_signed";
})(IdTokenType = exports.IdTokenType || (exports.IdTokenType = {}));
var VerifiablePresentationTypeFormat;
(function (VerifiablePresentationTypeFormat) {
    VerifiablePresentationTypeFormat["JWT_VP"] = "jwt_vp";
    VerifiablePresentationTypeFormat["LDP_VP"] = "ldp_vp";
})(VerifiablePresentationTypeFormat = exports.VerifiablePresentationTypeFormat || (exports.VerifiablePresentationTypeFormat = {}));
var VerifiableCredentialTypeFormat;
(function (VerifiableCredentialTypeFormat) {
    VerifiableCredentialTypeFormat["LDP_VC"] = "ldp_vc";
    VerifiableCredentialTypeFormat["JWT_VC"] = "jwt_vc";
})(VerifiableCredentialTypeFormat = exports.VerifiableCredentialTypeFormat || (exports.VerifiableCredentialTypeFormat = {}));
var EncSymmetricAlgorithmCode;
(function (EncSymmetricAlgorithmCode) {
    EncSymmetricAlgorithmCode["XC20P"] = "XC20P";
})(EncSymmetricAlgorithmCode = exports.EncSymmetricAlgorithmCode || (exports.EncSymmetricAlgorithmCode = {}));
var EncKeyAlgorithm;
(function (EncKeyAlgorithm) {
    EncKeyAlgorithm["ECDH_ES"] = "ECDH-ES";
})(EncKeyAlgorithm = exports.EncKeyAlgorithm || (exports.EncKeyAlgorithm = {}));
var PassBy;
(function (PassBy) {
    PassBy["NONE"] = "NONE";
    PassBy["REFERENCE"] = "REFERENCE";
    PassBy["VALUE"] = "VALUE";
})(PassBy = exports.PassBy || (exports.PassBy = {}));
var ResponseContext;
(function (ResponseContext) {
    ResponseContext["RP"] = "rp";
    ResponseContext["OP"] = "op";
})(ResponseContext = exports.ResponseContext || (exports.ResponseContext = {}));
var CheckLinkedDomain;
(function (CheckLinkedDomain) {
    CheckLinkedDomain["NEVER"] = "never";
    CheckLinkedDomain["IF_PRESENT"] = "if_present";
    CheckLinkedDomain["ALWAYS"] = "always";
})(CheckLinkedDomain = exports.CheckLinkedDomain || (exports.CheckLinkedDomain = {}));
var VerificationMode;
(function (VerificationMode) {
    VerificationMode[VerificationMode["INTERNAL"] = 0] = "INTERNAL";
    VerificationMode[VerificationMode["EXTERNAL"] = 1] = "EXTERNAL";
})(VerificationMode = exports.VerificationMode || (exports.VerificationMode = {}));
var GrantType;
(function (GrantType) {
    GrantType["AUTHORIZATION_CODE"] = "authorization_code";
    GrantType["IMPLICIT"] = "implicit";
})(GrantType = exports.GrantType || (exports.GrantType = {}));
var ResponseMode;
(function (ResponseMode) {
    ResponseMode["FRAGMENT"] = "fragment";
    ResponseMode["FORM_POST"] = "form_post";
    ResponseMode["POST"] = "post";
    ResponseMode["QUERY"] = "query";
})(ResponseMode = exports.ResponseMode || (exports.ResponseMode = {}));
var ProtocolFlow;
(function (ProtocolFlow) {
    ProtocolFlow["SAME_DEVICE"] = "same_device";
    ProtocolFlow["CROSS_DEVICE"] = "cross_device";
})(ProtocolFlow = exports.ProtocolFlow || (exports.ProtocolFlow = {}));
var UrlEncodingFormat;
(function (UrlEncodingFormat) {
    UrlEncodingFormat["FORM_URL_ENCODED"] = "application/x-www-form-urlencoded";
})(UrlEncodingFormat = exports.UrlEncodingFormat || (exports.UrlEncodingFormat = {}));
var KeyType;
(function (KeyType) {
    KeyType["EC"] = "EC";
})(KeyType = exports.KeyType || (exports.KeyType = {}));
var KeyCurve;
(function (KeyCurve) {
    KeyCurve["SECP256k1"] = "secp256k1";
    KeyCurve["ED25519"] = "ed25519";
})(KeyCurve = exports.KeyCurve || (exports.KeyCurve = {}));
var TokenEndpointAuthMethod;
(function (TokenEndpointAuthMethod) {
    TokenEndpointAuthMethod["CLIENT_SECRET_POST"] = "client_secret_post";
    TokenEndpointAuthMethod["CLIENT_SECRET_BASIC"] = "client_secret_basic";
    TokenEndpointAuthMethod["CLIENT_SECRET_JWT"] = "client_secret_jwt";
    TokenEndpointAuthMethod["PRIVATE_KEY_JWT"] = "private_key_jwt";
})(TokenEndpointAuthMethod = exports.TokenEndpointAuthMethod || (exports.TokenEndpointAuthMethod = {}));
var SigningAlgo;
(function (SigningAlgo) {
    SigningAlgo["EDDSA"] = "EdDSA";
    SigningAlgo["RS256"] = "RS256";
    SigningAlgo["PS256"] = "PS256";
    SigningAlgo["ES256"] = "ES256";
    SigningAlgo["ES256K"] = "ES256K";
})(SigningAlgo = exports.SigningAlgo || (exports.SigningAlgo = {}));
var Scope;
(function (Scope) {
    Scope["OPENID"] = "openid";
    Scope["OPENID_DIDAUTHN"] = "openid did_authn";
    //added based on the https://openid.net/specs/openid-connect-implicit-1_0.html#SelfIssuedDiscovery
    Scope["PROFILE"] = "profile";
    Scope["EMAIL"] = "email";
    Scope["ADDRESS"] = "address";
    Scope["PHONE"] = "phone";
})(Scope = exports.Scope || (exports.Scope = {}));
var ResponseType;
(function (ResponseType) {
    ResponseType["ID_TOKEN"] = "id_token";
    ResponseType["VP_TOKEN"] = "vp_token";
})(ResponseType = exports.ResponseType || (exports.ResponseType = {}));
var SubjectIdentifierType;
(function (SubjectIdentifierType) {
    SubjectIdentifierType["JKT"] = "jkt";
    SubjectIdentifierType["DID"] = "did";
})(SubjectIdentifierType = exports.SubjectIdentifierType || (exports.SubjectIdentifierType = {}));
var SubjectSyntaxTypesSupportedValues;
(function (SubjectSyntaxTypesSupportedValues) {
    SubjectSyntaxTypesSupportedValues["DID"] = "did";
    SubjectSyntaxTypesSupportedValues["JWK_THUMBPRINT"] = "urn:ietf:params:oauth:jwk-thumbprint";
})(SubjectSyntaxTypesSupportedValues = exports.SubjectSyntaxTypesSupportedValues || (exports.SubjectSyntaxTypesSupportedValues = {}));
var CredentialFormat;
(function (CredentialFormat) {
    CredentialFormat["JSON_LD"] = "w3cvc-jsonld";
    CredentialFormat["JWT"] = "jwt";
})(CredentialFormat = exports.CredentialFormat || (exports.CredentialFormat = {}));
var SubjectType;
(function (SubjectType) {
    SubjectType["PUBLIC"] = "public";
    SubjectType["PAIRWISE"] = "pairwise";
})(SubjectType = exports.SubjectType || (exports.SubjectType = {}));
var Schema;
(function (Schema) {
    Schema["OPENID"] = "openid:";
    Schema["OPENID_VC"] = "openid-vc:";
})(Schema = exports.Schema || (exports.Schema = {}));
var ResponseIss;
(function (ResponseIss) {
    ResponseIss["SELF_ISSUED_V1"] = "https://self-issued.me";
    ResponseIss["SELF_ISSUED_V2"] = "https://self-issued.me/v2";
    ResponseIss["JWT_VC_PRESENTATION_V1"] = "https://self-issued.me/v2/openid-vc";
})(ResponseIss = exports.ResponseIss || (exports.ResponseIss = {}));
const isInternalSignature = (object) => 'hexPrivateKey' in object && 'did' in object;
exports.isInternalSignature = isInternalSignature;
const isExternalSignature = (object) => 'signatureUri' in object && 'did' in object;
exports.isExternalSignature = isExternalSignature;
const isSuppliedSignature = (object) => 'signature' in object;
exports.isSuppliedSignature = isSuppliedSignature;
const isNoSignature = (object) => 'hexPublicKey' in object && 'did' in object;
exports.isNoSignature = isNoSignature;
const isRequestOpts = (object) => 'requestBy' in object;
exports.isRequestOpts = isRequestOpts;
const isResponseOpts = (object) => 'did' in object;
exports.isResponseOpts = isResponseOpts;
const isRequestPayload = (object) => 'response_mode' in object && 'response_type' in object;
exports.isRequestPayload = isRequestPayload;
const isResponsePayload = (object) => 'iss' in object && 'aud' in object;
exports.isResponsePayload = isResponsePayload;
const isInternalVerification = (object) => object.mode === VerificationMode.INTERNAL; /* && !isExternalVerification(object)*/
exports.isInternalVerification = isInternalVerification;
const isExternalVerification = (object) => object.mode === VerificationMode.EXTERNAL; /*&& 'verifyUri' in object || 'authZToken' in object*/
exports.isExternalVerification = isExternalVerification;
const isVP = (object) => 'presentation' in object;
exports.isVP = isVP;
const isPresentation = (object) => 'presentation_submission' in object;
exports.isPresentation = isPresentation;
var RevocationStatus;
(function (RevocationStatus) {
    RevocationStatus["VALID"] = "valid";
    RevocationStatus["INVALID"] = "invalid";
})(RevocationStatus = exports.RevocationStatus || (exports.RevocationStatus = {}));
var RevocationVerification;
(function (RevocationVerification) {
    RevocationVerification["NEVER"] = "never";
    RevocationVerification["IF_PRESENT"] = "if_present";
    RevocationVerification["ALWAYS"] = "always";
})(RevocationVerification = exports.RevocationVerification || (exports.RevocationVerification = {}));
var SupportedVersion;
(function (SupportedVersion) {
    SupportedVersion[SupportedVersion["SIOPv2_ID1"] = 70] = "SIOPv2_ID1";
    SupportedVersion[SupportedVersion["SIOPv2_D11"] = 110] = "SIOPv2_D11";
    SupportedVersion[SupportedVersion["JWT_VC_PRESENTATION_PROFILE_v1"] = 71] = "JWT_VC_PRESENTATION_PROFILE_v1";
})(SupportedVersion = exports.SupportedVersion || (exports.SupportedVersion = {}));
var ContentType;
(function (ContentType) {
    ContentType["FORM_URL_ENCODED"] = "application/x-www-form-urlencoded";
    ContentType["UTF_8"] = "UTF-8";
})(ContentType = exports.ContentType || (exports.ContentType = {}));
