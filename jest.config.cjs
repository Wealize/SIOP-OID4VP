module.exports = {
    preset: "ts-jest",
    testEnvironment: "node",
    moduleNameMapper: {
        "^jose/(.*)$": "<rootDir>/node_modules/jose/dist/node/cjs/$1",
    },
    rootDir: ".",
    roots: ["<rootDir>/src/", "<rootDir>/test/"],
    testMatch: ["**/?(*.)+(spec|test).+(ts|tsx|js)"],
    // transform: {
    //     "^.+\\.(ts|tsx)?$": "babel-jest",
    // },
    // transform: {}
    testPathIgnorePatterns: ["<rootDir>/node_modules/"],
    // transform: {
    //     "node_modules/variables/.+\\.(j|t)sx?$": "ts-jest"
    //   },
    // transformIgnorePatterns: [
    //     "node_modules/(?!variables/.*)"
    // ],
    moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json"],
    coverageDirectory: "./coverage/",
    collectCoverageFrom: [
        "src/**/*.{ts,tsx}",
        "!src/schemas/**",
        "!src/**/*.d.ts",
        "!**/node_modules/**",
        "!jest.config.cjs",
        "!generator/**",
        "!index.ts",

    ],
    collectCoverage: true,
    reporters: ["default", ["jest-junit", { outputDirectory: "./coverage" }]],
};
