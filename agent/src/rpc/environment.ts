import * as environment from "../generic/environment.js";

export const env = {
  // environment
  envAndroid: () => environment.androidPackage(),
  envAndroidPaths: () => environment.androidPaths(),
  envDarwinPaths: () => environment.darwinPaths(),
  envFrida: () => environment.frida(),
  envIos: () => environment.iosPackage(),
  envIosPaths: () => environment.iosPaths(),
  envRuntime: () => environment.runtime(),
};
