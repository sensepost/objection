import { clipboard } from "../android/clipboard";
import { androidfilesystem } from "../android/filesystem";
import { heap } from "../android/heap";
import { hooking } from "../android/hooking";
import { intent } from "../android/intent";
import { keystore } from "../android/keystore";
import { IHeapObject, IJavaField } from "../android/lib/interfaces";
import { ICurrentActivityFragment, IExecutedCommand, IKeyStoreEntry } from "../android/lib/interfaces";
import { sslpinning } from "../android/pinning";
import { root } from "../android/root";
import { androidshell } from "../android/shell";
import { userinterface } from "../android/userinterface";
import { proxy } from "../android/proxy";
import { general } from "../android/general";

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
  androidHookingGetClasses: (): Promise<string[]> => hooking.getClasses(),
  androidHookingGetClassLoaders: (): Promise<string[]> => hooking.getClassLoaders(),
  androidHookingGetCurrentActivity: (): Promise<ICurrentActivityFragment> => hooking.getCurrentActivity(),
  androidHookingListActivities: (): Promise<string[]> => hooking.getActivities(),
  androidHookingListBroadcastReceivers: (): Promise<string[]> => hooking.getBroadcastReceivers(),
  androidHookingListServices: (): Promise<string[]> => hooking.getServices(),
  androidHookingSetMethodReturn: (fqClazz: string, filterOverload: string | null, ret: boolean) =>
    hooking.setReturnValue(fqClazz, filterOverload, ret),
  androidHookingWatchClass: (clazz: string): Promise<void> => hooking.watchClass(clazz),
  androidHookingWatchMethod: (fqClazz: string, filterOverload: string | null, dargs: boolean,
                              dbt: boolean, dret: boolean): Promise<void> =>
    hooking.watchMethod(fqClazz, filterOverload, dargs, dbt, dret),

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
  androidKeystoreListDetails: () => keystore.listDetails(),
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
};
