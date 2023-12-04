import {
    CheckLinkedDomain,
    OP,
    PassBy,
    PresentationDefinitionLocation,
    PresentationExchange,
    PropertyTarget,
    RP,
    ResponseIss,
    ResponseMode,
    ResponseType,
    RevocationVerification,
    Scope,
    SigningAlgo,
    SubjectType,
    SupportedVersion,
    VPTokenLocation,
    encodeJsonAsURI,
} from "../src";

import { getResolver as EbsiResolver } from "@cef-ebsi/key-did-resolver";
import { SignJWT, importJWK } from "jose";

import {
    DIDResolutionOptions,
    DIDResolutionResult,
    Resolvable,
    Resolver,
    ResolverRegistry,
    parse
} from "did-resolver";

import { randomUUID } from "crypto";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import * as x25519 from "@transmute/did-key-web-crypto";
import { PresentationDefinitionV2 } from "@sphereon/pex-models";
import { JSONPath } from "@astronautlabs/jsonpath";

const VERIFIER_LOGO_FOR_CLIENT =
    "https://sphereon.com/content/themes/sphereon/assets/favicons/safari-pinned-tab.svg";
const VERIFIER_NAME_FOR_CLIENT = "Client Verifier Relying Party Sphereon INC";
const VERIFIERZ_PURPOSE_TO_VERIFY =
    "To request, receive and verify your credential about the the valid subject.";

const PUBLIC_KEY_JWK_RP = {
    "kty": "EC",
    "use": "sig",
    "crv": "P-256",
    "kid": "n5YCNxBcHlssfFN8Rh37zTe1_9YJRgsoH8sifVAb2cY",
    "x": "h7rj0PVORIkV6I6Hi44mgpN0V6RtPl9OkGNervwFz4g",
    "y": "qA5Iybhk0tF0lgLf_BSS-KpeaHUgNrSBCAqXAIlD93g",
    "alg": "ES256"
};
const PRIVATE_KEY_JWK_RP = {
    "kty": "EC",
    "d": "N-Rp9_fS2YcHK7yF6ZJezPhW2oXWPGS9ryASh7iJEN8",
    "use": "sig",
    "crv": "P-256",
    "kid": "n5YCNxBcHlssfFN8Rh37zTe1_9YJRgsoH8sifVAb2cY",
    "x": "h7rj0PVORIkV6I6Hi44mgpN0V6RtPl9OkGNervwFz4g",
    "y": "qA5Iybhk0tF0lgLf_BSS-KpeaHUgNrSBCAqXAIlD93g",
    "alg": "ES256"
};
const PUBLIC_KEY_JWK_OP = {
    "kty": "EC",
    "use": "sig",
    "crv": "P-256",
    "kid": "2uQOFvaPf1B6Maj1w5tjpoEPKp_zssYr_VOizlUoCac",
    "x": "7gvCT2QUy-hl0-xpl3_soH_OmzdLPMhtIf0leav5coM",
    "y": "n7t9vKOj6D3v4PidRiDMr1bGAWCvEaiueYNBXCEbFP0",
    "alg": "ES256"
};
const PRIVATE_KEY_JWK_OP = {
    "kty": "EC",
    "d": "YMDCQWA_xNjzhZ6FDaOnENzdytBc5t7kkHe8zcF69BQ",
    "use": "sig",
    "crv": "P-256",
    "kid": "2uQOFvaPf1B6Maj1w5tjpoEPKp_zssYr_VOizlUoCac",
    "x": "7gvCT2QUy-hl0-xpl3_soH_OmzdLPMhtIf0leav5coM",
    "y": "n7t9vKOj6D3v4PidRiDMr1bGAWCvEaiueYNBXCEbFP0",
    "alg": "ES256"
};
const PUBLIC_KEY_JWK_ISSUER = {
    kty: "EC",
    use: "sig",
    crv: "P-256",
    kid: "e15suic2LW6WMRR5XXGiOQjOoIztTQnoFjOYsu4aj7U",
    x: "bl-X38HVKC0XkwrhRU99mA5WA95YrC1lqz5Tv-A7Rbg",
    y: "VvfN7HO2VaCsK5rU1XaZkvDverFcy6DYt_qna1QRfYc",
    alg: "ES256"
};
const PRIVATE_KEY_JWK_ISSUER = {
    kty: "EC",
    d: "ja7hhftbyOiJX4Wtq_W7gDqpurSAu4m7otuqP81AOmk",
    use: "sig",
    crv: "P-256",
    kid: "e15suic2LW6WMRR5XXGiOQjOoIztTQnoFjOYsu4aj7U",
    x: "bl-X38HVKC0XkwrhRU99mA5WA95YrC1lqz5Tv-A7Rbg",
    y: "VvfN7HO2VaCsK5rU1XaZkvDverFcy6DYt_qna1QRfYc",
    alg: "ES256"
};

describe("Main test", () => {

    async function generateVC(
        _issuerDid,
        _kid,
        _privateKeyJwk,
        _publicKeyJwk,
        _subjectDid
    ) {
        // We concretised the entire credential due to a problem with Jest with the EBSI libraries,
        // which were to be used to generate the VC. Instead, the credential is inserted directly
        // with an expiry time of several years.
        return "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJraWQiOiJkaWQ6ZWJzaTp6ejdYc0M5aXhBWHVaZWNvRDlzWkVNMSNrTE1Nd012Z19NQUpHNnRQcVVVQVJyTlFocXhVU1BHdkJnMnNtQ3JMX2MwIn0.eyJqdGkiOiJ1cm46ZGlkOjEyMzQ1NiIsInN1YiI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUtib2kzQlNFNWJrM1lDR2VkekJ3OHFrbzdhM2pGeXR4eFhoTXczM2Y1U2d3dmV4aVRtQThCYlNmVzFXR2h2em91MUs3bmVlV1RGYXZUdjhjaVV2S1pIQnRpdWFKaTNBWkc3NWc3WEVEQkY2bUNvTThTdjQxTDZlZGZzQndHRXozVFpvMiIsImlzcyI6ImRpZDplYnNpOnp6N1hzQzlpeEFYdVplY29EOXNaRU0xIiwibmJmIjoxNjM1NzI0ODAwLCJleHAiOjE5NTM3NjMyMDAsImlhdCI6MTYzNTU1MjAwMCwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiaWQiOiJ1cm46ZGlkOjEyMzQ1NiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJWZXJpZmlhYmxlQXR0ZXN0YXRpb24iLCJWZXJpZmlhYmxlSWQiXSwiaXNzdWVyIjoiZGlkOmVic2k6eno3WHNDOWl4QVh1WmVjb0Q5c1pFTTEiLCJpc3N1YW5jZURhdGUiOiIyMDIxLTExLTAxVDAwOjAwOjAwWiIsInZhbGlkRnJvbSI6IjIwMjEtMTEtMDFUMDA6MDA6MDBaIiwidmFsaWRVbnRpbCI6IjIwMzMtMTEtMjlUMTI6MTM6MDIuNzc3WiIsImV4cGlyYXRpb25EYXRlIjoiMjAzMS0xMS0zMFQwMDowMDowMFoiLCJpc3N1ZWQiOiIyMDIxLTEwLTMwVDAwOjAwOjAwWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JvaTNCU0U1YmszWUNHZWR6Qnc4cWtvN2EzakZ5dHh4WGhNdzMzZjVTZ3d2ZXhpVG1BOEJiU2ZXMVdHaHZ6b3UxSzduZWVXVEZhdlR2OGNpVXZLWkhCdGl1YUppM0FaRzc1ZzdYRURCRjZtQ29NOFN2NDFMNmVkZnNCd0dFejNUWm8yIiwicGVyc29uYWxJZGVudGlmaWVyIjoiSVQvREUvMTIzNCIsImZhbWlseU5hbWUiOiJDYXN0YWZpb3JpIiwiZmlyc3ROYW1lIjoiQmlhbmNhIiwiZGF0ZU9mQmlydGgiOiIxOTMwLTEwLTAxIn0sImNyZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJodHRwczovL2FwaS1waWxvdC5lYnNpLmV1L3RydXN0ZWQtc2NoZW1hcy1yZWdpc3RyeS92My9zY2hlbWFzL3o4WTZKSm5lYlUyVXVRUU5jMlI4R1lxa0VpQU1qM0hkODYxclFoc29OV3hzTSIsInR5cGUiOiJGdWxsSnNvblNjaGVtYVZhbGlkYXRvcjIwMjEifSwidGVybXNPZlVzZSI6eyJpZCI6Imh0dHBzOi8vYXBpLXRlc3QuZWJzaS5ldS90cnVzdGVkLWlzc3VlcnMtcmVnaXN0cnkvdjUvaXNzdWVycy9kaWQ6ZWJzaTp6ejdYc0M5aXhBWHVaZWNvRDlzWkVNMS9hdHRyaWJ1dGVzLzcyMDFkOTVmZWYwNWY3MjY2N2Y1NDU0YzIxOTJkYTJhYTMwZDllMDUyZWVkZGVhNzY1MWI0NzcxOGQ2ZjMxYjAiLCJ0eXBlIjoiSXNzdWFuY2VDZXJ0aWZpY2F0ZSJ9fX0._xCpKYtBuZ6lmfDp4lWURkyRgtaYEa2YS38ugaPEIW1MO8MPQM68uUG5cJDucHMU1W6MzXo_p4LiqFih_MWAKw";
    }

    it("Login with VP Token", async () => {
        // We are going to use EBSI identifiers
        const rpDid = EbsiWallet.createDid("NATURAL_PERSON", PUBLIC_KEY_JWK_RP);
        const opDid = EbsiWallet.createDid("NATURAL_PERSON", PUBLIC_KEY_JWK_OP);
        const issuerDid = EbsiWallet.createDid("LEGAL_ENTITY");
        const vc = await generateVC(
            issuerDid,
            PUBLIC_KEY_JWK_ISSUER.kid,
            PRIVATE_KEY_JWK_ISSUER,
            PUBLIC_KEY_JWK_ISSUER,
            opDid
        );
        const { didDocument: rpDidDoc, keys: rpKeys } = await x25519.generate({
            kty: "EC",
            crvOrSize: "P-256",
        });
        const { didDocument: opDidDoc, keys: opKeys } = await x25519.generate({
            kty: "EC",
            crvOrSize: "P-256",
        });
        const rpPrivKeyHex = Buffer.from(PRIVATE_KEY_JWK_RP.d, "base64url").toString("hex")
        const opPrivKeyHex = Buffer.from(PRIVATE_KEY_JWK_OP.d, "base64url").toString("hex")

        const presentationDefinitionId = randomUUID();
        const nonce = randomUUID();

        // Presentation definicion, Sphereon does not support the combination of array + contains
        // Here we are requesting a credential with a field "familyName" of type string
        const pDefinition: PresentationDefinitionV2 = {
            id: presentationDefinitionId,
            input_descriptors: [
                {
                    id: "FirstIdExample",
                    name: "FirstVCTypeExample",
                    constraints: {
                        fields: [
                            {
                                path: [
                                    "$.credentialSubject.familyName"
                                ],
                                filter: {
                                    type: "string",
                                    // contains: { const: "VerifiableId" }
                                }
                            }
                        ]
                    }
                },
            ],
        }

        // CREATE RP
        const relayingParty = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
            .withClientId("test_client_id")
            .withScope("test")
            .withResponseType([ResponseType.ID_TOKEN, ResponseType.VP_TOKEN])
            .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
            .withRevocationVerification(RevocationVerification.NEVER)
            // Specifies that the did:key method is supported. Sphereon shall query a universal registry for the DIDs of this method that are communicated to it.
            // .addDidMethod("key")
            // Specified that the did:key methos is supported and also how to resolve the DIDs
            // .addResolver(
            //     "key",
            //     new Resolver(getUniResolver("key", { resolveUrl: "https://dev.uniresolver.io/" }))
            // )
            .withRedirectUri("https://redirect.me")
            .withRequestByValue()
            // The definition can be also specified at the request level.
            .withPresentationDefinition(
                { definition: pDefinition },
                [
                    PropertyTarget.REQUEST_OBJECT,
                    PropertyTarget.AUTHORIZATION_REQUEST
                ]
            )
            // A callback that is executed when a VP is verified and can be used to perform additional checks.
            .withPresentationVerification(async (_presentation) => { return { verified: true } })
            // .withRequestByReference(`https://example.izertis.com/blockchain/auth-requests/${randomUUID()}`)
            .withResponseMode(ResponseMode.POST)
            .withClientMetadata({
                passBy: PassBy.VALUE, // Reference implies a fetch request
                // reference_uri: "https://registration.here",
                logo_uri: VERIFIER_LOGO_FOR_CLIENT,
                clientName: VERIFIER_NAME_FOR_CLIENT,
                clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
            })
            .withInternalSignature(
                rpPrivKeyHex,
                rpDidDoc.id,
                `${rpDidDoc.id}#${rpDidDoc.id.substring(8)}`,
                SigningAlgo.ES256
            )
            .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
            .withClientMetadata({
                client_id: 'https://www.example.com/.well-known/client_id',
                idTokenSigningAlgValuesSupported: [SigningAlgo.ES256],
                requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256],
                responseTypesSupported: [ResponseType.ID_TOKEN],
                vpFormatsSupported: { jwt_va: { alg: [SigningAlgo.ES256] } },
                scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
                subjectTypesSupported: [SubjectType.PAIRWISE],
                passBy: PassBy.VALUE,
                logo_uri: VERIFIER_LOGO_FOR_CLIENT,
                clientName: VERIFIER_NAME_FOR_CLIENT,
            })
            .build();

        const authRequest = await relayingParty.createAuthorizationRequest({
            correlationId: "1453",
            nonce,
            state: "example-state",
            // claims: {
            //     vp_token: {
            //         presentation_definition: pDefinition,
            //     },
            // }
        });

        const authRequestUri = await authRequest.uri();

        // TODO: Resolvers are desactivated
        class CustomResolver implements Resolvable {
            registry: ResolverRegistry;
            constructor(registry: ResolverRegistry = {}) {
                this.registry = registry;
            }
            async resolve(didUrl: string, options: DIDResolutionOptions = {}): Promise<DIDResolutionResult> {
                const parsed = parse(didUrl)
                const resolver = this.registry[parsed.method]
                return resolver(parsed.did, parsed, this, options);
            }
        }

        // CREATE OP
        const openidProvider = OP.builder()
            .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
            //   .addDidMethod("did:key")
            .addResolver(
                "key",
                // new Resolver(getUniResolver("key", { resolveUrl: "https://dev.uniresolver.io/" }))
                new CustomResolver(EbsiResolver())
            )
            .withIssuer(ResponseIss.SELF_ISSUED_V2)
            .withResponseMode(ResponseMode.POST)
            .withInternalSignature(
                opPrivKeyHex,
                opDidDoc.id,
                `${opDidDoc.id}#${opDidDoc.id.substring(8)}`,
                SigningAlgo.ES256
            )
            .withExpiresIn(1000)
            .withSupportedVersions([SupportedVersion.SIOPv2_ID1])
            .withRegistration({
                authorizationEndpoint: 'www.myauthorizationendpoint.com',
                idTokenSigningAlgValuesSupported: [SigningAlgo.ES256],
                issuer: ResponseIss.SELF_ISSUED_V2,
                requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256],
                responseTypesSupported: [ResponseType.ID_TOKEN, ResponseType.VP_TOKEN],
                vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
                scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
                subjectTypesSupported: [SubjectType.PAIRWISE],
                subject_syntax_types_supported: [],
                passBy: PassBy.VALUE,
                logo_uri: VERIFIER_LOGO_FOR_CLIENT,
                clientName: VERIFIER_NAME_FOR_CLIENT,
            })
            .build();

        const verifiedReq = await openidProvider.verifyAuthorizationRequest(authRequestUri);
        // If the presentation definition was correct it should be present in the verifiedReq
        expect(verifiedReq.presentationDefinitions.length).toBe(1);
        const pDefinitionReceived = verifiedReq.presentationDefinitions[0];
        // This object basically manages the credentials to be worked with.
        const pex = new PresentationExchange({
            allDIDs: [opDid],
            allVerifiableCredentials: [vc]
        });
        // This method checks each of the submitted credentials and verifies whether any of them meet the submission requirements.
        // Note that there may be more than one alternative. If so, it is up to the user to select which one to continue with.
        const checked = await pex.selectVerifiableCredentialsForSubmission(pDefinitionReceived.definition);
        expect(checked.errors.length).toBe(0);
        expect(checked.matches.length).toBe(1);
        // We retrieve the valid credentials from the SelectResult object 
        const result = JSONPath.query(checked, checked.matches[0].vc_path[0]);
        expect(result.length).toBe(1);
        const selectedCredentials = result[0];
        // VP creation
        const verifiablePresentationResult = await pex.createVerifiablePresentation(
            pDefinitionReceived.definition,
            selectedCredentials,
            async (args) => {
                // We could add here the nonce to prevent reply attacks, although it will be added
                // in the Auth response
                const privKey = await importJWK(PRIVATE_KEY_JWK_OP)
                const header = {
                    typ: "JWT",
                    alg: "ES256",
                    kid: "Gi4WgBtlg2ChnSpesSYG-Z-4dXFpjk2yr9NeF488YT0" // JWK Thumprint
                };
                args.presentation.holder = opDid;
                return await new SignJWT({ vp: args.presentation, nonce })
                    .setIssuer(opDid)
                    .setAudience(rpDid)
                    .setSubject(opDid)
                    .setProtectedHeader(header)
                    .sign(privKey)
            },
            // { presentationSubmissionLocation: 0 } // Does not work for now
        );
        const vp = verifiablePresentationResult.verifiablePresentation;
        // Auth Response
        const authResponse = await openidProvider.createAuthorizationResponse(
            verifiedReq,
            {
                presentationExchange: {
                    verifiablePresentations: [vp],
                    vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
                    presentationSubmission: verifiablePresentationResult.presentationSubmission
                }
            }
        );
        // After this we are ready to send the response
        // The body to send should be equal to authResponseAsURI
        const _authResponseAsURI = encodeJsonAsURI(authResponse.response.payload);
        // console.log(authResponseAsURI);
        // Since the redirect_uri is https://redirect.me, the method wont fail
        await openidProvider.submitAuthorizationResponse(authResponse);
        // At last, the RP verify the Auth Response
        const verifiedResponse = await relayingParty.verifyAuthorizationResponse(
            authResponse.response.payload,
            {
                presentationDefinitions: [
                    {
                        definition: pDefinition,
                        location: PresentationDefinitionLocation.CLAIMS_VP_TOKEN
                    }
                ]
            }
        );
        console.log(verifiedResponse);
    });
});
