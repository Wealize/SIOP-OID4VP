"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LanguageTagUtils = void 0;
const language_tags_1 = __importDefault(require("language-tags"));
const types_1 = require("../types");
const ObjectUtils_1 = require("./ObjectUtils");
class LanguageTagUtils {
    /**
     * It will give back a fields which are language tag enabled. i.e. all fields with the fields names containing
     * language tags e.g. fieldName#nl-NL
     *
     * @param source is the object from which the language enabled fields and their values will be extracted.
     */
    static getAllLanguageTaggedProperties(source) {
        return this.getLanguageTaggedPropertiesMapped(source, undefined);
    }
    /**
     * It will give back a fields which are language tag enabled and are listed in the required fields.
     *
     * @param source is the object from which the language enabled fields and their values will be extracted.
     * @param requiredFieldNames the fields which are supposed to be language enabled. These are the only fields which should be returned.
     */
    static getLanguageTaggedProperties(source, requiredFieldNames) {
        const languageTagEnabledFieldsNamesMapping = new Map();
        requiredFieldNames.forEach((value) => languageTagEnabledFieldsNamesMapping.set(value, value));
        return this.getLanguageTaggedPropertiesMapped(source, languageTagEnabledFieldsNamesMapping);
    }
    /**
     * It will give back a fields which are language tag enabled and are mapped in the required fields.
     *
     * @param source is the object from which the language enabled fields and their values will be extracted.
     * @param requiredFieldNamesMapping the fields which are supposed to be language enabled. These are the only fields which should be returned. And
     *                                  the fields names will be transformed as per the mapping provided.
     */
    static getLanguageTaggedPropertiesMapped(source, requiredFieldNamesMapping) {
        this.assertSourceIsWorthChecking(source);
        this.assertValidTargetFieldNames(requiredFieldNamesMapping);
        const discoveredLanguageTaggedFields = new Map();
        Object.entries(source).forEach(([key, value]) => {
            const languageTagSeparatorIndexInKey = key.indexOf(this.LANGUAGE_TAG_SEPARATOR);
            if (this.isFieldLanguageTagged(languageTagSeparatorIndexInKey)) {
                this.extractLanguageTaggedField(key, value, languageTagSeparatorIndexInKey, requiredFieldNamesMapping, discoveredLanguageTaggedFields);
            }
        });
        return discoveredLanguageTaggedFields;
    }
    static extractLanguageTaggedField(key, value, languageTagSeparatorIndexInKey, languageTagEnabledFieldsNamesMapping, languageTaggedFields) {
        const fieldName = this.getFieldName(key, languageTagSeparatorIndexInKey);
        const languageTag = this.getLanguageTag(key, languageTagSeparatorIndexInKey);
        if (language_tags_1.default.check(languageTag)) {
            if (languageTagEnabledFieldsNamesMapping === null || languageTagEnabledFieldsNamesMapping === void 0 ? void 0 : languageTagEnabledFieldsNamesMapping.size) {
                if (languageTagEnabledFieldsNamesMapping.has(fieldName)) {
                    languageTaggedFields.set(this.getMappedFieldName(languageTagEnabledFieldsNamesMapping, fieldName, languageTag), value);
                }
            }
            else {
                languageTaggedFields.set(key, value);
            }
        }
    }
    static getMappedFieldName(languageTagEnabledFieldsNamesMapping, fieldName, languageTag) {
        return languageTagEnabledFieldsNamesMapping.get(fieldName) + this.LANGUAGE_TAG_SEPARATOR + languageTag;
    }
    static getLanguageTag(key, languageTagSeparatorIndex) {
        return key.substring(languageTagSeparatorIndex + 1);
    }
    static getFieldName(key, languageTagSeparatorIndex) {
        return key.substring(0, languageTagSeparatorIndex);
    }
    /***
     * This function checks about the field to be language-tagged.
     *
     * @param languageTagSeparatorIndex
     * @private
     */
    static isFieldLanguageTagged(languageTagSeparatorIndex) {
        return languageTagSeparatorIndex > 0;
    }
    static assertValidTargetFieldNames(languageTagEnabledFieldsNamesMapping) {
        if (languageTagEnabledFieldsNamesMapping) {
            if (!languageTagEnabledFieldsNamesMapping.size) {
                throw new Error(types_1.SIOPErrors.BAD_PARAMS + ' LanguageTagEnabledFieldsNamesMapping must be non-null or non-empty');
            }
            else {
                for (const entry of languageTagEnabledFieldsNamesMapping.entries()) {
                    const key = entry[0];
                    const value = entry[1];
                    if ((0, ObjectUtils_1.isStringNullOrEmpty)(key) || (0, ObjectUtils_1.isStringNullOrEmpty)(value)) {
                        throw new Error(types_1.SIOPErrors.BAD_PARAMS + '. languageTagEnabledFieldsName must be non-null or non-empty');
                    }
                }
            }
        }
    }
    static assertSourceIsWorthChecking(source) {
        if (!source) {
            throw new Error(types_1.SIOPErrors.BAD_PARAMS + ' Source must be non-null i.e. not-initialized.');
        }
    }
}
exports.LanguageTagUtils = LanguageTagUtils;
LanguageTagUtils.LANGUAGE_TAG_SEPARATOR = '#';
