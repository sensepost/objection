import { binarycookies } from "../ios/binarycookies";
import { credentialstorage } from "../ios/credentialstorage";
import { iosfilesystem } from "../ios/filesystem";
import { hooking } from "../ios/hooking";
import { iosjailbreak } from "../ios/jailbreak";
import { ioskeychain } from "../ios/keychain";
import { ICredential, IIosCookie, IIosFileSystem, IKeychainItem } from "../ios/lib/interfaces";
import { NSUserDefaults } from "../ios/lib/types";
import { nsuserdefaults } from "../ios/nsuserdefaults";
import { pasteboard } from "../ios/pasteboard";
import { sslpinning } from "../ios/pinning";
import { plist } from "../ios/plist";
import { userinterface } from "../ios/userinterface";

export const ios = {
  // ios binary cookies
  iosCookiesGet: (): IIosCookie[] => binarycookies.get(),

  // ios nsurlcredentialstorage
  iosCredentialStorage: (): ICredential[] => credentialstorage.dump(),

  // ios filesystem
  iosFileCwd: (): string => iosfilesystem.pwd(),
  iosFileDownload: (path: string): Buffer => iosfilesystem.readFile(path),
  iosFileExists: (path: string): boolean => iosfilesystem.exists(path),
  iosFileLs: (path: string): IIosFileSystem => iosfilesystem.ls(path),
  iosFilePathIsFile: (path: string): boolean => iosfilesystem.pathIsFile(path),
  iosFileReadable: (path: string): boolean => iosfilesystem.readable(path),
  iosFileUpload: (path: string, data: string): void => iosfilesystem.writeFile(path, data),
  iosFileWritable: (path: string): boolean => iosfilesystem.writable(path),

  // ios hooking
  iosHookingGetClassMethods: (className: string, includeParents: boolean): string[] =>
    hooking.getClassMethods(className, includeParents),
  iosHookingGetClasses: () => hooking.getClasses(),
  iosHookingSearchMethods: (partial: string): string[] => hooking.searchMethods(partial),
  iosHookingSetReturnValue: (selector: string, returnVal: boolean): void =>
    hooking.setMethodReturn(selector, returnVal),
  iosHookingWatchClass: (clazz: string, parents: boolean): void => hooking.watchClass(clazz, parents),
  iosHookingWatchMethod: (selector: string, dargs: boolean, dbt: boolean, dret: boolean): void =>
    hooking.watchMethod(selector, dargs, dbt, dret),

  // jailbreak detection
  iosJailbreakDisable: (): void => iosjailbreak.disable(),
  iosJailbreakEnable: (): void => iosjailbreak.enable(),

  // plist files
  iosPlistRead: (path: string): string => plist.read(path),

  // ios user interface
  iosUiAlert: (message: string): void => userinterface.alert(message),
  iosUiBiometricsBypass: (): void => userinterface.biometricsBypass(),
  iosUiScreenshot: (): any => userinterface.screenshot(),
  iosUiWindowDump: (): string => userinterface.dump(),

  // ios ssl pinning
  iosPinningDisable: (quiet: boolean): void => sslpinning.disable(quiet),

  // ios pasteboard
  iosMonitorPasteboard: (): void => pasteboard.monitor(),

  // ios keychain
  iosKeychainAdd: (key: string, data: string): boolean => ioskeychain.add(key, data),
  iosKeychainEmpty: (): void => ioskeychain.empty(),
  iosKeychainList: (): IKeychainItem[] => ioskeychain.list(),

  // ios nsuserdefaults
  iosNsuserDefaultsGet: (): NSUserDefaults | any => nsuserdefaults.get(),
};
