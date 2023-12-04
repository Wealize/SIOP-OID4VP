"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
__exportStar(require("./AuthorizationRequestPayloadVID1.schema"), exports);
__exportStar(require("./AuthorizationRequestPayloadVD11.schema"), exports);
// export * from './AuthorizationRequestOpts.schema';
__exportStar(require("./AuthorizationResponseOpts.schema"), exports);
__exportStar(require("./DiscoveryMetadataPayload.schema"), exports);
__exportStar(require("./RPRegistrationMetadataPayload.schema"), exports);
__exportStar(require("./validation"), exports);
