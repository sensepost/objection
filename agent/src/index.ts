import { AndroidFilesystem } from "./android/filesystem";
import { environment } from "./generic/environment";
import { binarycookies } from "./ios/binarycookies";
import { credentialstorage } from "./ios/credentialstorage";
import { iosfilesystem } from "./ios/filesystem";
import { hooking } from "./ios/hooking";
import { iosjailbreak } from "./ios/jailbreak";
import { ioskeychain } from "./ios/keychain";
import { nsuserdefaults } from "./ios/nsuserdefaults";
import { pasteboard } from "./ios/pasteboard";
import { sslpinning } from "./ios/pinning";
import { plist } from "./ios/plist";
import { userinterface } from "./ios/userinterface";
import { jobs } from "./lib/jobs";
import { version } from "./version";

const androidfilesystem: AndroidFilesystem = new AndroidFilesystem();

rpc.exports = {

  // environment
  envAndroid: () => environment.androidPackage(),
  envAndroidPaths: () => environment.androidPaths(),
  envFrida: () => environment.frida(),
  envIos: () => environment.iosPackage(),
  envIosPaths: () => environment.iosPaths(),
  envRuntime: () => environment.runtime(),

  // jobs
  jobsGet: () => jobs.all(),
  jobsKill: (ident: string) => jobs.kill(ident),

  // android filesystem
  androidFileLs: (path: string) => androidfilesystem.ls(path),

  // ios binary cookies
  iosCookiesGet: () => binarycookies.get(),

  // ios nsurlcredentialstorage
  iosCredentialStorage: () => credentialstorage.dump(),

  // ios filesystem
  iosFileCwd: () => iosfilesystem.pwd(),
  iosFileDownload: (path: string) => iosfilesystem.readFile(path),
  iosFileExists: (path: string) => iosfilesystem.exists(path),
  iosFileLs: (path: string) => iosfilesystem.ls(path),
  iosFilePathIsFile: (path: string) => iosfilesystem.pathIsFile(path),
  iosFileReadable: (path: string) => iosfilesystem.readable(path),
  iosFileUpload: (path: string, data: string) => iosfilesystem.writeFile(path, data),
  iosFileWritable: (path: string) => iosfilesystem.writable(path),

  // ios hooking
  iosHookingGetClassMethods: (className: string, includeParents: boolean) =>
    hooking.getClassMethods(className, includeParents),
  iosHookingGetClasses: () => hooking.getClasses(),
  iosHookingSearchMethods: (partial: string) => hooking.searchMethods(partial),
  iosHookingSetReturnValue: (selector: string, returnVal: boolean) =>
    hooking.setMethodReturn(selector, returnVal),
  iosHookingWatchClass: (clazz: string, parents: boolean) => hooking.watchClass(clazz, parents),
  iosHookingWatchMethod: (selector: string, dargs: boolean, dbt: boolean, dret: boolean) =>
    hooking.watchMethod(selector, dargs, dbt, dret),

  // jailbreak detection
  iosJailbreakDisable: () => iosjailbreak.disable(),

  // plist files
  iosPlistRead: (path: string) => plist.read(path),

  // ios user interface
  iosUiAlert: (message: string) => userinterface.alert(message),
  iosUiBiometricsBypass: () => userinterface.biometricsBypass(),
  iosUiScreenshot: () => userinterface.screenshot(),
  iosUiWindowDump: () => userinterface.dump(),

  // ios ssl pinning
  iosPinningDisable: (quiet: boolean) => sslpinning.disable(quiet),

  // ios pasteboard
  iosMonitorPasteboard: () => pasteboard.monitor(),

  // keychain
  keychainAdd: (key: string, data: string) => ioskeychain.add(key, data),
  keychainEmpty: () => ioskeychain.empty(),
  keychainList: () => ioskeychain.list(),

  // nsuserdefaults
  nsuserDefaults: () => nsuserdefaults.get(),

  // meta
  version: () => version,
};
