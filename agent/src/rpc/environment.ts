import * as environment from "../generic/environment.js";

export const env = {
  // environment
  envAndroid: () => environment.androidPackage(),
  envAndroidPaths: () => environment.androidPaths(),
  envFrida: () => environment.frida(),
  envIos: () => environment.iosPackage(),
  envIosPaths: () => environment.iosPaths(),
  envRuntime: () => environment.runtime(),
};
