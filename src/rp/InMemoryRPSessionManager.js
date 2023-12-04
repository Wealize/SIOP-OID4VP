"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InMemoryRPSessionManager = void 0;
const types_1 = require("../types");
/**
 * Please note that this session manager is not really meant to be used in large production settings, as it stores everything in memory!
 * It also doesn't do scheduled cleanups. It runs a cleanup whenever a request or response is received. In a high-volume production setting you will want scheduled cleanups running in the background
 * Since this is a low level library we have not created a full-fledged implementation.
 * We suggest to create your own implementation using the event system of the library
 */
class InMemoryRPSessionManager {
    static getKeysForCorrelationId(mapping, correlationId) {
        return Object.entries(mapping)
            .filter((entry) => entry[1] === correlationId)
            .map((filtered) => Number.parseInt(filtered[0]));
    }
    constructor(eventEmitter, opts) {
        var _a;
        this.authorizationRequests = {};
        this.authorizationResponses = {};
        // stored by hashcode
        this.nonceMapping = {};
        // stored by hashcode
        this.stateMapping = {};
        if (!eventEmitter) {
            throw Error('RP Session manager depends on an event emitter in the application');
        }
        this.maxAgeInSeconds = (_a = opts === null || opts === void 0 ? void 0 : opts.maxAgeInSeconds) !== null && _a !== void 0 ? _a : 5 * 60;
        eventEmitter.on(types_1.AuthorizationEvents.ON_AUTH_REQUEST_CREATED_SUCCESS, this.onAuthorizationRequestCreatedSuccess.bind(this));
        eventEmitter.on(types_1.AuthorizationEvents.ON_AUTH_REQUEST_CREATED_FAILED, this.onAuthorizationRequestCreatedFailed.bind(this));
        eventEmitter.on(types_1.AuthorizationEvents.ON_AUTH_REQUEST_SENT_SUCCESS, this.onAuthorizationRequestSentSuccess.bind(this));
        eventEmitter.on(types_1.AuthorizationEvents.ON_AUTH_REQUEST_SENT_FAILED, this.onAuthorizationRequestSentFailed.bind(this));
        eventEmitter.on(types_1.AuthorizationEvents.ON_AUTH_RESPONSE_RECEIVED_SUCCESS, this.onAuthorizationResponseReceivedSuccess.bind(this));
        eventEmitter.on(types_1.AuthorizationEvents.ON_AUTH_RESPONSE_RECEIVED_FAILED, this.onAuthorizationResponseReceivedFailed.bind(this));
        eventEmitter.on(types_1.AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_SUCCESS, this.onAuthorizationResponseVerifiedSuccess.bind(this));
        eventEmitter.on(types_1.AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_FAILED, this.onAuthorizationResponseVerifiedFailed.bind(this));
    }
    async getRequestStateByCorrelationId(correlationId, errorOnNotFound) {
        return await this.getFromMapping('correlationId', correlationId, this.authorizationRequests, errorOnNotFound);
    }
    async getRequestStateByNonce(nonce, errorOnNotFound) {
        return await this.getFromMapping('nonce', nonce, this.authorizationRequests, errorOnNotFound);
    }
    async getRequestStateByState(state, errorOnNotFound) {
        return await this.getFromMapping('state', state, this.authorizationRequests, errorOnNotFound);
    }
    async getResponseStateByCorrelationId(correlationId, errorOnNotFound) {
        return await this.getFromMapping('correlationId', correlationId, this.authorizationResponses, errorOnNotFound);
    }
    async getResponseStateByNonce(nonce, errorOnNotFound) {
        return await this.getFromMapping('nonce', nonce, this.authorizationResponses, errorOnNotFound);
    }
    async getResponseStateByState(state, errorOnNotFound) {
        return await this.getFromMapping('state', state, this.authorizationResponses, errorOnNotFound);
    }
    async getFromMapping(type, value, mapping, errorOnNotFound) {
        const correlationId = await this.getCorrelationIdImpl(type, value, errorOnNotFound);
        const result = mapping[correlationId];
        if (!result && errorOnNotFound) {
            throw Error(`Could not find ${type} from correlation id ${correlationId}`);
        }
        return result;
    }
    async onAuthorizationRequestCreatedSuccess(event) {
        this.cleanup().catch((error) => console.log(JSON.stringify(error)));
        this.updateState('request', event, types_1.AuthorizationRequestStateStatus.CREATED).catch((error) => console.log(JSON.stringify(error)));
    }
    async onAuthorizationRequestCreatedFailed(event) {
        this.cleanup().catch((error) => console.log(JSON.stringify(error)));
        this.updateState('request', event, types_1.AuthorizationRequestStateStatus.ERROR).catch((error) => console.log(JSON.stringify(error)));
    }
    async onAuthorizationRequestSentSuccess(event) {
        this.cleanup().catch((error) => console.log(JSON.stringify(error)));
        this.updateState('request', event, types_1.AuthorizationRequestStateStatus.SENT).catch((error) => console.log(JSON.stringify(error)));
    }
    async onAuthorizationRequestSentFailed(event) {
        this.cleanup().catch((error) => console.log(JSON.stringify(error)));
        this.updateState('request', event, types_1.AuthorizationRequestStateStatus.ERROR).catch((error) => console.log(JSON.stringify(error)));
    }
    async onAuthorizationResponseReceivedSuccess(event) {
        this.cleanup().catch((error) => console.log(JSON.stringify(error)));
        await this.updateState('response', event, types_1.AuthorizationResponseStateStatus.RECEIVED);
    }
    async onAuthorizationResponseReceivedFailed(event) {
        this.cleanup().catch((error) => console.log(JSON.stringify(error)));
        await this.updateState('response', event, types_1.AuthorizationResponseStateStatus.ERROR);
    }
    async onAuthorizationResponseVerifiedFailed(event) {
        await this.updateState('response', event, types_1.AuthorizationResponseStateStatus.ERROR);
    }
    async onAuthorizationResponseVerifiedSuccess(event) {
        await this.updateState('response', event, types_1.AuthorizationResponseStateStatus.VERIFIED);
    }
    async getCorrelationIdByNonce(nonce, errorOnNotFound) {
        return await this.getCorrelationIdImpl('nonce', nonce, errorOnNotFound);
    }
    async getCorrelationIdByState(state, errorOnNotFound) {
        return await this.getCorrelationIdImpl('state', state, errorOnNotFound);
    }
    async getCorrelationIdImpl(type, value, errorOnNotFound) {
        if (!value || !type) {
            throw Error('No type or value provided');
        }
        if (type === 'correlationId') {
            return value;
        }
        const hash = await hashCode(value);
        const correlationId = type === 'nonce' ? this.nonceMapping[hash] : this.stateMapping[hash];
        if (!correlationId && errorOnNotFound) {
            throw Error(`Could not find ${type} value for ${value}`);
        }
        return correlationId;
    }
    async updateMapping(mapping, event, key, value, allowExisting) {
        const hash = await hashcodeForValue(event, key);
        const existing = mapping[hash];
        if (existing) {
            if (!allowExisting) {
                throw Error(`Mapping exists for key ${key} and we do not allow overwriting values`);
            }
            else if (value && existing !== value) {
                throw Error('Value changed for key');
            }
        }
        if (!value) {
            delete mapping[hash];
        }
        else {
            mapping[hash] = value;
        }
    }
    async updateState(type, event, status) {
        if (!event) {
            throw new Error('event not present');
        }
        else if (!event.correlationId) {
            throw new Error(`'${type} ${status}' event without correlation id received`);
        }
        try {
            const eventState = Object.assign(Object.assign(Object.assign(Object.assign({ correlationId: event.correlationId }, (type === 'request' ? { request: event.subject } : {})), (type === 'response' ? { response: event.subject } : {})), (event.error ? { error: event.error } : {})), { status, timestamp: event.timestamp, lastUpdated: event.timestamp });
            if (type === 'request') {
                this.authorizationRequests[event.correlationId] = eventState;
                // We do not await these
                this.updateMapping(this.nonceMapping, event, 'nonce', event.correlationId, true).catch((error) => console.log(JSON.stringify(error)));
                this.updateMapping(this.stateMapping, event, 'state', event.correlationId, true).catch((error) => console.log(JSON.stringify(error)));
            }
            else {
                this.authorizationResponses[event.correlationId] = eventState;
            }
        }
        catch (error) {
            console.log(`Error in update state happened: ${error}`);
            // TODO VDX-166 handle error
        }
    }
    async deleteStateForCorrelationId(correlationId) {
        InMemoryRPSessionManager.cleanMappingForCorrelationId(this.nonceMapping, correlationId).catch((error) => console.log(JSON.stringify(error)));
        InMemoryRPSessionManager.cleanMappingForCorrelationId(this.stateMapping, correlationId).catch((error) => console.log(JSON.stringify(error)));
        delete this.authorizationRequests[correlationId];
        delete this.authorizationResponses[correlationId];
    }
    static async cleanMappingForCorrelationId(mapping, correlationId) {
        const keys = InMemoryRPSessionManager.getKeysForCorrelationId(mapping, correlationId);
        if (keys && keys.length > 0) {
            keys.forEach((key) => delete mapping[key]);
        }
    }
    async cleanup() {
        const now = Date.now();
        const maxAgeInMS = this.maxAgeInSeconds * 1000;
        const cleanupCorrelations = (reqByCorrelationId) => {
            const correlationId = reqByCorrelationId[0];
            const authRequest = reqByCorrelationId[1];
            if (authRequest) {
                const ts = authRequest.lastUpdated || authRequest.timestamp;
                if (maxAgeInMS !== 0 && now > ts + maxAgeInMS) {
                    this.deleteStateForCorrelationId(correlationId);
                }
            }
        };
        Object.entries(this.authorizationRequests).forEach((reqByCorrelationId) => {
            cleanupCorrelations.call(this, reqByCorrelationId);
        });
        Object.entries(this.authorizationResponses).forEach((resByCorrelationId) => {
            cleanupCorrelations.call(this, resByCorrelationId);
        });
    }
}
exports.InMemoryRPSessionManager = InMemoryRPSessionManager;
async function hashcodeForValue(event, key) {
    const value = (await event.subject.getMergedProperty(key));
    if (!value) {
        throw Error(`No value found for key ${key} in Authorization Request`);
    }
    return hashCode(value);
}
function hashCode(s) {
    let h = 1;
    for (let i = 0; i < s.length; i++)
        h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
    return h;
}
