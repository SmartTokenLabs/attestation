module.exports = {
    roots: ['<rootDir>/src'],
    transform: {
        '^.+\\.tsx?$': 'ts-jest',
    },
    testEnvironment: "jsdom",
    testRegex: '(/__tests__/.*|(\\.|/)(test|spec))\\.tsx?$',
    moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
    moduleNameMapper: {
        "^multiformats$": "<rootDir>/node_modules/multiformats/cjs/src/index.js",
    }
}
