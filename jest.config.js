export default {
  coverageDirectory: 'coverage',
  coverageProvider: 'v8',
  testEnvironment: 'node',
  // preset: 'ts-jest/presets/default-esm', TODO: check when https://github.com/kulshekhar/ts-jest/issues/3800 lands
  extensionsToTreatAsEsm: ['.ts'],
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        useESM: true,
        isolatedModules: true,
      },
    ],
  },
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  testRegex: 'tests/.*\\.test\\.ts',
  testTimeout: 10_000,
};
