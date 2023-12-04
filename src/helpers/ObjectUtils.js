"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.removeNullUndefined = exports.isStringNullOrEmpty = exports.extractDataFromPath = void 0;
const jsonpath_1 = require("@astronautlabs/jsonpath");
function extractDataFromPath(obj, path) {
    return jsonpath_1.JSONPath.nodes(obj, path);
}
exports.extractDataFromPath = extractDataFromPath;
function isStringNullOrEmpty(key) {
    return !key || !key.length;
}
exports.isStringNullOrEmpty = isStringNullOrEmpty;
function removeNullUndefined(data) {
    if (!data) {
        return data;
    }
    //transform properties into key-values pairs and filter all the empty-values
    const entries = Object.entries(data).filter(([, value]) => value != null);
    //map through all the remaining properties and check if the value is an object.
    //if value is object, use recursion to remove empty properties
    const clean = entries.map(([key, v]) => {
        const value = typeof v === 'object' && !Array.isArray(v) ? removeNullUndefined(v) : v;
        return [key, value];
    });
    //transform the key-value pairs back to an object.
    return Object.fromEntries(clean);
}
exports.removeNullUndefined = removeNullUndefined;
