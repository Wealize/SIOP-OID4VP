"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PresentationExchange = void 0;
const pex_1 = require("@sphereon/pex");
const ssi_types_1 = require("@sphereon/ssi-types");
const helpers_1 = require("../helpers");
const types_1 = require("../types");
const types_2 = require("./types");
class PresentationExchange {
    constructor(opts) {
        this.pex = new pex_1.PEX();
        this.allDIDs = opts.allDIDs;
        this.allVerifiableCredentials = opts.allVerifiableCredentials;
    }
    /**
     * Construct presentation submission from selected credentials
     * @param presentationDefinition payload object received by the OP from the RP
     * @param selectedCredentials
     * @param presentationSignCallback
     * @param options
     */
    async createVerifiablePresentation(presentationDefinition, selectedCredentials, presentationSignCallback, 
    // options2?: { nonce?: string; domain?: string, proofType?: IProofType, verificationMethod?: string, signatureKeyEncoding?: KeyEncoding },
    options) {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j;
        if (!presentationDefinition) {
            throw new Error(types_1.SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
        }
        const signOptions = Object.assign(Object.assign({}, options), { proofOptions: {
                proofPurpose: (_b = (_a = options === null || options === void 0 ? void 0 : options.proofOptions) === null || _a === void 0 ? void 0 : _a.proofPurpose) !== null && _b !== void 0 ? _b : ssi_types_1.IProofPurpose.authentication,
                type: (_d = (_c = options === null || options === void 0 ? void 0 : options.proofOptions) === null || _c === void 0 ? void 0 : _c.type) !== null && _d !== void 0 ? _d : ssi_types_1.IProofType.EcdsaSecp256k1Signature2019,
                challenge: (_e = options === null || options === void 0 ? void 0 : options.proofOptions) === null || _e === void 0 ? void 0 : _e.challenge,
                domain: (_f = options === null || options === void 0 ? void 0 : options.proofOptions) === null || _f === void 0 ? void 0 : _f.domain,
            }, signatureOptions: {
                verificationMethod: (_g = options === null || options === void 0 ? void 0 : options.signatureOptions) === null || _g === void 0 ? void 0 : _g.verificationMethod,
                keyEncoding: (_j = (_h = options === null || options === void 0 ? void 0 : options.signatureOptions) === null || _h === void 0 ? void 0 : _h.keyEncoding) !== null && _j !== void 0 ? _j : pex_1.KeyEncoding.Hex,
            } });
        return await this.pex.verifiablePresentationFrom(presentationDefinition, selectedCredentials, presentationSignCallback, signOptions);
    }
    /**
     * This method will be called from the OP when we are certain that we have a
     * PresentationDefinition object inside our requestPayload
     * Finds a set of `VerifiableCredential`s from a list supplied to this class during construction,
     * matching presentationDefinition object found in the requestPayload
     * if requestPayload doesn't contain any valid presentationDefinition throws an error
     * if PEX library returns any error in the process, throws the error
     * returns the SelectResults object if successful
     * @param presentationDefinition object received by the OP from the RP
     * @param opts
     */
    async selectVerifiableCredentialsForSubmission(presentationDefinition, opts) {
        var _a;
        if (!presentationDefinition) {
            throw new Error(types_1.SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
        }
        else if (!this.allVerifiableCredentials || this.allVerifiableCredentials.length == 0) {
            throw new Error(`${types_1.SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, no VCs were provided`);
        }
        const selectResults = this.pex.selectFrom(presentationDefinition, this.allVerifiableCredentials, Object.assign(Object.assign({}, opts), { holderDIDs: (_a = opts === null || opts === void 0 ? void 0 : opts.holderDIDs) !== null && _a !== void 0 ? _a : this.allDIDs, 
            // fixme limited disclosure
            limitDisclosureSignatureSuites: [] }));
        if (selectResults.areRequiredCredentialsPresent == pex_1.Status.ERROR) {
            throw new Error(`message: ${types_1.SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(selectResults.errors)}`);
        }
        return selectResults;
    }
    /**
     * validatePresentationAgainstDefinition function is called mainly by the RP
     * after receiving the VP from the OP
     * @param presentationDefinition object containing PD
     * @param verifiablePresentation
     * @param opts
     */
    static async validatePresentationAgainstDefinition(presentationDefinition, verifiablePresentation, opts) {
        const wvp = typeof verifiablePresentation === 'object' && 'original' in verifiablePresentation
            ? verifiablePresentation
            : ssi_types_1.CredentialMapper.toWrappedVerifiablePresentation(verifiablePresentation);
        if (!presentationDefinition) {
            throw new Error(types_1.SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
        }
        else if (!wvp || !wvp.presentation || !wvp.presentation.verifiableCredential || wvp.presentation.verifiableCredential.length === 0) {
            throw new Error(types_1.SIOPErrors.NO_VERIFIABLE_PRESENTATION_NO_CREDENTIALS);
        }
        // console.log(`Presentation (validate): ${JSON.stringify(verifiablePresentation)}`);
        const evaluationResults = new pex_1.PEX().evaluatePresentation(presentationDefinition, wvp.original, opts);
        if (evaluationResults.errors.length) {
            throw new Error(`message: ${types_1.SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(evaluationResults.errors)}`);
        }
        return evaluationResults;
    }
    static assertValidPresentationSubmission(presentationSubmission) {
        const validationResult = pex_1.PEX.validateSubmission(presentationSubmission);
        if (validationResult[0].message != 'ok') {
            throw new Error(`${types_1.SIOPErrors.RESPONSE_OPTS_PRESENTATIONS_SUBMISSION_IS_NOT_VALID}, details ${JSON.stringify(validationResult[0])}`);
        }
    }
    /**
     * Finds a valid PresentationDefinition inside the given AuthenticationRequestPayload
     * throws exception if the PresentationDefinition is not valid
     * returns null if no property named "presentation_definition" is found
     * returns a PresentationDefinition if a valid instance found
     * @param authorizationRequestPayload object that can have a presentation_definition inside
     * @param version
     */
    static async findValidPresentationDefinitions(authorizationRequestPayload, version) {
        const allDefinitions = [];
        async function extractDefinitionFromVPToken() {
            const vpTokens = (0, helpers_1.extractDataFromPath)(authorizationRequestPayload, '$..vp_token.presentation_definition').map((d) => d.value);
            const vpTokenRefs = (0, helpers_1.extractDataFromPath)(authorizationRequestPayload, '$..vp_token.presentation_definition_uri');
            if (vpTokens && vpTokens.length && vpTokenRefs && vpTokenRefs.length) {
                throw new Error(types_1.SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_BY_REF_AND_VALUE_NON_EXCLUSIVE);
            }
            if (vpTokens && vpTokens.length) {
                vpTokens.forEach((vpToken) => {
                    if (allDefinitions.find((value) => value.definition.id === vpToken.id)) {
                        console.log(`Warning. We encountered presentation definition with id ${vpToken.id}, more then once whilst processing! Make sure your payload is valid!`);
                        return;
                    }
                    PresentationExchange.assertValidPresentationDefinition(vpToken);
                    allDefinitions.push({
                        definition: vpToken,
                        location: types_2.PresentationDefinitionLocation.CLAIMS_VP_TOKEN,
                        version,
                    });
                });
            }
            else if (vpTokenRefs && vpTokenRefs.length) {
                for (const vpTokenRef of vpTokenRefs) {
                    const pd = (await (0, helpers_1.getWithUrl)(vpTokenRef.value));
                    if (allDefinitions.find((value) => value.definition.id === pd.id)) {
                        console.log(`Warning. We encountered presentation definition with id ${pd.id}, more then once whilst processing! Make sure your payload is valid!`);
                        return;
                    }
                    PresentationExchange.assertValidPresentationDefinition(pd);
                    allDefinitions.push({ definition: pd, location: types_2.PresentationDefinitionLocation.CLAIMS_VP_TOKEN, version });
                }
            }
        }
        function addSingleToplevelPDToPDs(definition, version) {
            if (allDefinitions.find((value) => value.definition.id === definition.id)) {
                console.log(`Warning. We encountered presentation definition with id ${definition.id}, more then once whilst processing! Make sure your payload is valid!`);
                return;
            }
            PresentationExchange.assertValidPresentationDefinition(definition);
            allDefinitions.push({
                definition: definition,
                location: types_2.PresentationDefinitionLocation.TOPLEVEL_PRESENTATION_DEF,
                version,
            });
        }
        async function extractDefinitionFromTopLevelDefinitionProperty(version) {
            const definitions = (0, helpers_1.extractDataFromPath)(authorizationRequestPayload, '$.presentation_definition');
            const definitionsFromList = (0, helpers_1.extractDataFromPath)(authorizationRequestPayload, '$.presentation_definition[*]');
            const definitionRefs = (0, helpers_1.extractDataFromPath)(authorizationRequestPayload, '$.presentation_definition_uri');
            const definitionRefsFromList = (0, helpers_1.extractDataFromPath)(authorizationRequestPayload, '$.presentation_definition_uri[*]');
            const hasPD = (definitions && definitions.length > 0) || (definitionsFromList && definitionsFromList.length > 0);
            const hasPdRef = (definitionRefs && definitionRefs.length > 0) || (definitionRefsFromList && definitionRefsFromList.length > 0);
            if (hasPD && hasPdRef) {
                throw new Error(types_1.SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_BY_REF_AND_VALUE_NON_EXCLUSIVE);
            }
            if (definitions && definitions.length > 0) {
                definitions.forEach((definition) => {
                    addSingleToplevelPDToPDs(definition.value, version);
                });
            }
            else if (definitionsFromList && definitionsFromList.length > 0) {
                definitionsFromList.forEach((definition) => {
                    addSingleToplevelPDToPDs(definition.value, version);
                });
            }
            else if (definitionRefs && definitionRefs.length > 0) {
                for (const definitionRef of definitionRefs) {
                    const pd = await (0, helpers_1.getWithUrl)(definitionRef.value);
                    addSingleToplevelPDToPDs(pd, version);
                }
            }
            else if (definitionsFromList && definitionRefsFromList.length > 0) {
                for (const definitionRef of definitionRefsFromList) {
                    const pd = await (0, helpers_1.getWithUrl)(definitionRef.value);
                    addSingleToplevelPDToPDs(pd, version);
                }
            }
        }
        if (authorizationRequestPayload) {
            if (!version || version < types_1.SupportedVersion.SIOPv2_D11) {
                await extractDefinitionFromVPToken();
            }
            await extractDefinitionFromTopLevelDefinitionProperty();
        }
        return allDefinitions;
    }
    static assertValidPresentationDefinitionWithLocations(definitionsWithLocations) {
        if (definitionsWithLocations && definitionsWithLocations.length > 0) {
            definitionsWithLocations.forEach((definitionWithLocation) => PresentationExchange.assertValidPresentationDefinition(definitionWithLocation.definition));
        }
    }
    static assertValidPresentationDefinition(presentationDefinition) {
        const validationResult = pex_1.PEX.validateDefinition(presentationDefinition);
        if (validationResult[0].message != 'ok') {
            throw new Error(`${types_1.SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID}`);
        }
    }
    static async validatePresentationsAgainstDefinitions(definitions, vpPayloads, verifyPresentationCallback, opts) {
        if (!definitions || !vpPayloads || !definitions.length || definitions.length !== vpPayloads.length) {
            throw new Error(types_1.SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD);
        }
        await Promise.all(definitions.map(async (pd) => await PresentationExchange.validatePresentationsAgainstDefinition(pd.definition, vpPayloads, verifyPresentationCallback, opts)));
    }
    static async validatePresentationsAgainstDefinition(definition, vpPayloads, verifyPresentationCallback, opts) {
        var _a;
        const pex = new pex_1.PEX();
        function filterOutCorrectPresentation() {
            //TODO: add support for multiple VPs here
            return vpPayloads.filter(async (vpw) => {
                var _a;
                const presentationSubmission = (_a = opts === null || opts === void 0 ? void 0 : opts.presentationSubmission) !== null && _a !== void 0 ? _a : vpw.presentation.presentation_submission;
                const presentation = vpw.presentation;
                if (!definition) {
                    throw new Error(types_1.SIOPErrors.NO_PRESENTATION_SUBMISSION);
                }
                else if (!presentation || !presentation.verifiableCredential || presentation.verifiableCredential.length === 0) {
                    throw new Error(types_1.SIOPErrors.NO_VERIFIABLE_PRESENTATION_NO_CREDENTIALS);
                }
                // The verifyPresentationCallback function is mandatory for RP only,
                // So the behavior here is to bypass it if not present
                if (verifyPresentationCallback) {
                    try {
                        await verifyPresentationCallback(vpw.original);
                    }
                    catch (error) {
                        throw new Error(types_1.SIOPErrors.VERIFIABLE_PRESENTATION_SIGNATURE_NOT_VALID);
                    }
                }
                // console.log(`Presentation (filter): ${JSON.stringify(presentation)}`);
                const evaluationResults = pex.evaluatePresentation(definition, vpw.original, Object.assign(Object.assign({}, opts), { presentationSubmission }));
                const submission = evaluationResults.value;
                if (!presentation || !submission) {
                    throw new Error(types_1.SIOPErrors.NO_PRESENTATION_SUBMISSION);
                }
                return submission && submission.definition_id === definition.id;
            });
        }
        const checkedPresentations = filterOutCorrectPresentation();
        if (!checkedPresentations.length || checkedPresentations.length != 1) {
            throw new Error(`${types_1.SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}`);
        }
        const checkedPresentation = checkedPresentations[0];
        const presentation = checkedPresentation.presentation;
        // console.log(`Presentation (checked): ${JSON.stringify(checkedPresentation.presentation)}`);
        if (!presentation || !presentation.verifiableCredential || presentation.verifiableCredential.length === 0) {
            throw new Error(types_1.SIOPErrors.NO_VERIFIABLE_PRESENTATION_NO_CREDENTIALS);
        }
        const presentationSubmission = (_a = opts === null || opts === void 0 ? void 0 : opts.presentationSubmission) !== null && _a !== void 0 ? _a : presentation.presentation_submission;
        const evaluationResults = pex.evaluatePresentation(definition, checkedPresentation.original, Object.assign(Object.assign({}, opts), { presentationSubmission }));
        PresentationExchange.assertValidPresentationSubmission(evaluationResults.value);
        await PresentationExchange.validatePresentationAgainstDefinition(definition, checkedPresentation, Object.assign(Object.assign({}, opts), { presentationSubmission }));
    }
}
exports.PresentationExchange = PresentationExchange;
