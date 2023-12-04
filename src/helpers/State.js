"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createState = exports.getState = exports.toNonce = exports.getNonce = void 0;
const sha_js_1 = __importDefault(require("sha.js"));
const uuid_1 = require("uuid");
const Encodings_1 = require("./Encodings");
function getNonce(state, nonce) {
    return nonce || toNonce(state);
}
exports.getNonce = getNonce;
function toNonce(input) {
    const buff = (0, sha_js_1.default)('sha256').update(input).digest();
    return (0, Encodings_1.base64urlEncodeBuffer)(buff);
}
exports.toNonce = toNonce;
function getState(state) {
    return state || createState();
}
exports.getState = getState;
function createState() {
    return (0, uuid_1.v4)();
}
exports.createState = createState;
