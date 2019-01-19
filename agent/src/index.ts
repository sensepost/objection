import { clipboard } from "./android/clipboard";
import { androidfilesystem } from "./android/filesystem";
import { hooking as androidhooking } from "./android/hooking";
import { intent } from "./android/intent";
import { keystore } from "./android/keystore";
import { IExecutedCommand, IKeyStoreEntry } from "./android/lib/interfaces";
import { sslpinning as androidsslpinning } from "./android/pinning";
import { androidshell } from "./android/shell";
import { environment } from "./generic/environment";
import { binarycookies } from "./ios/binarycookies";
import { credentialstorage } from "./ios/credentialstorage";
import { iosfilesystem } from "./ios/filesystem";
import { hooking as ioshooking } from "./ios/hooking";
import { iosjailbreak } from "./ios/jailbreak";
import { ioskeychain } from "./ios/keychain";
import { nsuserdefaults } from "./ios/nsuserdefaults";
import { pasteboard } from "./ios/pasteboard";
import { sslpinning as iossslpinning } from "./ios/pinning";
import { plist } from "./ios/plist";
import { userinterface } from "./ios/userinterface";
import { jobs } from "./lib/jobs";
import { version } from "./version";

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

  // android clipboard
  androidMonitorClipboard: () => clipboard.monitor(),

  // android command execution
  androidShellExec: (cmd: string): Promise<IExecutedCommand> => androidshell.execute(cmd),

  // android filesystem
  androidFileCwd: () => androidfilesystem.pwd(),
  androidFileDownload: (path: string) => androidfilesystem.readFile(path),
  androidFileExists: (path: string) => androidfilesystem.exists(path),
  androidFileLs: (path: string) => androidfilesystem.ls(path),
  androidFilePathIsFile: (path: string) => androidfilesystem.pathIsFile(path),
  androidFileReadable: (path: string) => androidfilesystem.readable(path),
  androidFileUpload: (path: string, data: string) => androidfilesystem.writeFile(path, data),
  androidFileWritable: (path: string) => androidfilesystem.writable(path),

  // android hooking
  androidHookingGetClassMethods: (className: string): Promise<string[]> => androidhooking.getClassMethods(className),
  androidHookingGetClasses: (): Promise<string[]> => androidhooking.getClasses(),
  androidHookingListActivities: (): Promise<string[]> => androidhooking.getActivities(),
  androidHookingListBroadcastReceivers: (): Promise<string[]> => androidhooking.getBroadcastReceivers(),
  androidHookingListServices: (): Promise<string[]> => androidhooking.getServices(),
  androidHookingSetMethodReturn: (fqClazz: string, ret: boolean) => androidhooking.setReturnValue(fqClazz, ret),
  androidHookingWatchClass: (clazz: string): Promise<void> => androidhooking.watchClass(clazz),
  androidHookingWatchMethod: (fqClazz: string, dargs: boolean, dbt: boolean, dret: boolean): Promise<void> =>
    androidhooking.watchMethod(fqClazz, dargs, dbt, dret),

  // android intents
  androidIntentStartActivity: (activityClass: string): Promise<void> => intent.startActivity(activityClass),
  androidIntentStartService: (serviceClass: string): Promise<void> => intent.startService(serviceClass),

  // android keystore
  androidKeystoreClear: () => keystore.clear(),
  androidKeystoreList: (): Promise<IKeyStoreEntry[]> => keystore.list(),

  // android ssl pinning
  androidSslPinningDisable: (quiet: boolean) => androidsslpinning.disable(quiet),

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
    ioshooking.getClassMethods(className, includeParents),
  iosHookingGetClasses: () => ioshooking.getClasses(),
  iosHookingSearchMethods: (partial: string) => ioshooking.searchMethods(partial),
  iosHookingSetReturnValue: (selector: string, returnVal: boolean) =>
    ioshooking.setMethodReturn(selector, returnVal),
  iosHookingWatchClass: (clazz: string, parents: boolean) => ioshooking.watchClass(clazz, parents),
  iosHookingWatchMethod: (selector: string, dargs: boolean, dbt: boolean, dret: boolean) =>
    ioshooking.watchMethod(selector, dargs, dbt, dret),

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
  iosPinningDisable: (quiet: boolean) => iossslpinning.disable(quiet),

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
