import * as binary from "../ios/binary.js";
import * as binarycookies from "../ios/binarycookies.js";
import * as bundles from "../ios/bundles.js";
import * as credentialstorage from "../ios/credentialstorage.js";
import * as iosfilesystem from "../ios/filesystem.js";
import * as heap from "../ios/heap.js";
import * as hooking from "../ios/hooking.js";
import * as ioscrypto from "../ios/crypto.js";
import * as iosjailbreak from "../ios/jailbreak.js";
import * as ioskeychain from "../ios/keychain.js";
import * as nsuserdefaults from "../ios/nsuserdefaults.js";
import * as pasteboard from "../ios/pasteboard.js";
import * as sslpinning from "../ios/pinning.js";
import * as plist from "../ios/plist.js";
import * as userinterface from "../ios/userinterface.js";

import { BundleType } from "../ios/lib/constants.js";
import { NSUserDefaults } from "../ios/lib/types.js";
import {
  IBinaryModuleDictionary,
  ICredential,
  IFramework,
  IHeapObject,
  IIosCookie,
  IIosFileSystem,
  IKeychainItem,
} from "../ios/lib/interfaces.js";


export const ios = {
  // binary
  iosBinaryInfo: (): IBinaryModuleDictionary => binary.info(),

  // ios binary cookies
  iosCookiesGet: (): IIosCookie[] => binarycookies.get(),

  // ios nsurlcredentialstorage
  iosCredentialStorage: (): ICredential[] => credentialstorage.dump(),

  // ios filesystem
  iosFileCwd: (): string => iosfilesystem.pwd(),
  iosFileDelete: (path: string): boolean => iosfilesystem.deleteFile(path),
  iosFileDownload: (path: string): Buffer => iosfilesystem.readFile(path),
  iosFileExists: (path: string): boolean => iosfilesystem.exists(path),
  iosFileLs: (path: string): IIosFileSystem => iosfilesystem.ls(path),
  iosFilePathIsFile: (path: string): boolean => iosfilesystem.pathIsFile(path),
  iosFileReadable: (path: string): boolean => iosfilesystem.readable(path),
  iosFileUpload: (path: string, data: string): void => iosfilesystem.writeFile(path, data),
  iosFileWritable: (path: string): boolean => iosfilesystem.writable(path),

  // ios heap
  iosHeapEvaluateJs: (pointer: string, js: string): void => heap.evaluate(pointer, js),
  iosHeapExecMethod: (pointer: string, method: string, returnString: boolean): void =>
    heap.callInstanceMethod(pointer, method, returnString),
  iosHeapPrintIvars: (pointer: string, toUTF8: boolean): [string, any[string]] => heap.getIvars(pointer, toUTF8),
  iosHeapPrintLiveInstances: (clazz: string): IHeapObject[] => heap.getInstances(clazz),
  iosHeapPrintMethods: (pointer: string): [string, any[string]] => heap.getMethods(pointer),

  // ios hooking
  iosHookingGetClassMethods: (className: string, includeParents: boolean): string[] =>
    hooking.getClassMethods(className, includeParents),
  iosHookingGetClasses: () => hooking.getClasses(),
  iosHookingSetReturnValue: (selector: string, returnVal: boolean): void =>
    hooking.setMethodReturn(selector, returnVal),
  iosHookingWatch: (pattern: string, dargs: boolean, dbt: boolean, dret: boolean, dparents: boolean) =>
    hooking.watch(pattern, dargs, dbt, dret, dparents),
  iosHookingSearch: (pattern: string): ApiResolverMatch[] =>
    hooking.search(pattern),

  // ios crypto monitoring
  iosMonitorCryptoEnable: (): void => ioscrypto.monitor(),

  // jailbreak detection
  iosJailbreakDisable: (): void => iosjailbreak.disable(),
  iosJailbreakEnable: (): void => iosjailbreak.enable(),

  // plist files
  iosPlistRead: (path: string): string => plist.read(path),

  // ios user interface
  iosUiAlert: (message: string): void => userinterface.alert(message),
  iosUiBiometricsBypass: (): void => userinterface.biometricsBypass(),
  iosUiScreenshot: (): any => userinterface.take(),
  iosUiWindowDump: (): string => userinterface.dump(),

  // ios ssl pinning
  iosPinningDisable: (quiet: boolean): void => sslpinning.disable(quiet),

  // ios pasteboard
  iosMonitorPasteboard: (): void => pasteboard.monitor(),

  // ios frameworks & bundles
  iosBundlesGetBundles: (): IFramework[] => bundles.getBundles(BundleType.NSBundleAllBundles),
  iosBundlesGetFrameworks: (): IFramework[] => bundles.getBundles(BundleType.NSBundleFramework),

  // ios keychain
  iosKeychainAdd: (account: string, service: string, data: string): boolean =>
    ioskeychain.add(account, service, data),
  iosKeychainRemove: (account: string, service: string): void => ioskeychain.remove(account, service),
  iosKeychainUpdate: (account: string, service: string, newData: string): void =>
    ioskeychain.update(account, service, newData),
  iosKeychainEmpty: (): void => ioskeychain.empty(),
  iosKeychainList: (smartDecode: boolean = false): IKeychainItem[] => ioskeychain.list(smartDecode),
  iosKeychainListRaw: (): void => ioskeychain.listRaw(),

  // ios nsuserdefaults
  iosNsuserDefaultsGet: (): NSUserDefaults | any => nsuserdefaults.get(),
};
