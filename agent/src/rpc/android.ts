import * as clipboard from "../android/clipboard";
import * as androidfilesystem from "../android/filesystem";
import * as heap from "../android/heap";
import * as hooking from "../android/hooking";
import * as intent from "../android/intent";
import * as keystore from "../android/keystore";
import * as sslpinning from "../android/pinning";
import * as root from "../android/root";
import * as androidshell from "../android/shell";
import * as userinterface from "../android/userinterface";
import * as proxy from "../android/proxy";
import * as sharedprefs from "../android/sharedprefs";
import * as general from "../android/general";

import {
  IHeapObject,
  IJavaField,
  IKeyStoreDetail
} from "../android/lib/interfaces";
import {
  ICurrentActivityFragment,
  IExecutedCommand,
  IKeyStoreEntry
} from "../android/lib/interfaces";
import { JavaMethodsOverloadsResult } from "../android/lib/types";

export const android = {
  // android clipboard
  androidMonitorClipboard: () => clipboard.monitor(),

  // android general
  androidDeoptimize: () => general.deoptimize(),

  // android command execution
  androidShellExec: (cmd: string): Promise<IExecutedCommand> => androidshell.execute(cmd),

  // android filesystem
  androidFileCwd: () => androidfilesystem.pwd(),
  androidFileDelete: (path: string) => androidfilesystem.deleteFile(path),
  androidFileDownload: (path: string) => androidfilesystem.readFile(path),
  androidFileExists: (path: string) => androidfilesystem.exists(path),
  androidFileLs: (path: string) => androidfilesystem.ls(path),
  androidFilePathIsFile: (path: string) => androidfilesystem.pathIsFile(path),
  androidFileReadable: (path: string) => androidfilesystem.readable(path),
  androidFileUpload: (path: string, data: string) => androidfilesystem.writeFile(path, data),
  androidFileWritable: (path: string) => androidfilesystem.writable(path),

  // android hooking
  androidHookingGetClassMethods: (className: string): Promise<string[]> => hooking.getClassMethods(className),
  androidHookingGetClassMethodsOverloads: (className: string, methodAllowList: string[] = [], loader?: string): Promise<JavaMethodsOverloadsResult> => hooking.getClassMethodsOverloads(className, methodAllowList, loader),
  androidHookingGetClasses: (): Promise<string[]> => hooking.getClasses(),
  androidHookingGetClassLoaders: (): Promise<string[]> => hooking.getClassLoaders(),
  androidHookingGetCurrentActivity: (): Promise<ICurrentActivityFragment> => hooking.getCurrentActivity(),
  androidHookingListActivities: (): Promise<string[]> => hooking.getActivities(),
  androidHookingListBroadcastReceivers: (): Promise<string[]> => hooking.getBroadcastReceivers(),
  androidHookingListServices: (): Promise<string[]> => hooking.getServices(),
  androidHookingSetMethodReturn: (fqClazz: string, filterOverload: string | null, ret: boolean) =>
    hooking.setReturnValue(fqClazz, filterOverload, ret),
  androidHookingWatch: (pattern: string, watchArgs: boolean, watchBacktrace: boolean, watchRet: boolean): Promise<void> =>
    hooking.watch(pattern, watchArgs, watchBacktrace, watchRet),
  androidHookingEnumerate: (query: string): Promise<Java.EnumerateMethodsMatchGroup[]> => hooking.javaEnumerate(query),
  androidHookingLazyWatchForPattern: (query: string, watch: boolean, dargs: boolean, dret: boolean, dbt: boolean): void => hooking.lazyWatchForPattern(query, watch, dargs, dret, dbt),

  // android heap methods
  androidHeapEvaluateHandleMethod: (handle: number, js: string): Promise<void> => heap.evaluate(handle, js),
  androidHeapExecuteHandleMethod: (handle: number, method: string, returnString: boolean): Promise<string | null> =>
    heap.execute(handle, method, returnString),
  androidHeapGetLiveClassInstances: (clazz: string): Promise<IHeapObject[]> => heap.getInstances(clazz),
  androidHeapPrintFields: (handle: number): Promise<IJavaField[]> => heap.fields(handle),
  androidHeapPrintMethods: (handle: number): Promise<string[]> => heap.methods(handle),

  // android intents
  androidIntentStartActivity: (activityClass: string): Promise<void> => intent.startActivity(activityClass),
  androidIntentStartService: (serviceClass: string): Promise<void> => intent.startService(serviceClass),

  // android keystore
  androidKeystoreClear: () => keystore.clear(),
  androidKeystoreList: (): Promise<IKeyStoreEntry[]> => keystore.list(),
  androidKeystoreDetail: (): Promise<IKeyStoreDetail[]> => keystore.detail(),
  androidKeystoreWatch: (): void => keystore.watchKeystore(),

  // android ssl pinning
  androidSslPinningDisable: (quiet: boolean) => sslpinning.disable(quiet),

  // android proxy set/unset
  androidProxySet: (host: string, port: string): Promise<void> => proxy.set(host, port),

  // android root detection
  androidRootDetectionDisable: () => root.disable(),
  androidRootDetectionEnable: () => root.enable(),

  // android user interface
  androidUiScreenshot: () => userinterface.screenshot(),
  androidUiSetFlagSecure: (v: boolean): Promise<void> => userinterface.setFlagSecure(v),

  // android shared preferences
  androidSharedprefsMonitor: (encrypted_only: boolean) => sharedprefs.monitor(encrypted_only),
};
