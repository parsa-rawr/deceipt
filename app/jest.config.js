/**
 * Jest configuration.
 *
 * `transformIgnorePatterns` is the standard React Native entry for the one
 * reason it exists: some packages publish untranspiled ESM, and Jest's default
 * Node transform rejects it with "Cannot use import statement outside a module".
 * `react-native-camera-kit` is such a package, so it is added to the allowlist
 * alongside the react-native family.
 *
 * Note for anyone extending this: adding a dependency that ships ESM will fail
 * every suite that imports it until it is listed here, and the failure names the
 * file rather than the dependency.
 */
module.exports = {
  preset: '@react-native/jest-preset',
  // AsyncStorage ships untranspiled ESM, so it must be transformed rather than
  // read straight from node_modules; the camera package is stubbed (below) for a
  // different reason.
  transformIgnorePatterns: ['node_modules/(?!(@react-native|react-native|@react-native-async-storage)/)'],
  moduleNameMapper: {
    // The camera package ships a compiled spec that RN's babel codegen plugin
    // rejects under Jest, and a native view cannot render in Node. The stub is a
    // boundary double so the scan -> selection path stays testable.
    '^react-native-camera-kit$': '<rootDir>/tests/mocks/react-native-camera-kit.tsx',
  },
};
