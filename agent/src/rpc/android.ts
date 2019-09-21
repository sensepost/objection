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

export const android = {
  // android clipboard
  androidMonitorClipboard: () => clipboard.monitor(),

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
  androidHookingGetCurrentActivity: (): Promise<ICurrentActivityFragment> => hooking.getCurrentActivity(),
  androidHookingListActivities: (): Promise<string[]> => hooking.getActivities(),
  androidHookingListBroadcastReceivers: (): Promise<string[]> => hooking.getBroadcastReceivers(),
  androidHookingListServices: (): Promise<string[]> => hooking.getServices(),
  androidHookingSetMethodReturn: (fqClazz: string, ret: boolean) => hooking.setReturnValue(fqClazz, ret),
  androidHookingWatchClass: (clazz: string): Promise<void> => hooking.watchClass(clazz),
  androidHookingWatchMethod: (fqClazz: string, dargs: boolean, dbt: boolean, dret: boolean): Promise<void> =>
    hooking.watchMethod(fqClazz, dargs, dbt, dret),

  // android heap methods
  androidHeapEvaluateHandleMethod: (handle: string, js: string): Promise<void> => heap.evaluate(handle, js),
  androidHeapExecuteHandleMethod: (handle: string, method: string, returnString: boolean): Promise<string|null> =>
    heap.execute(handle, method, returnString),
  androidHeapGetLiveClassInstances: (clazz: string, fresh: boolean): Promise<IHeapObject[]> =>
    heap.getInstances(clazz, fresh),
  androidHeapPrintFields: (handle: string): Promise<IJavaField[]> => heap.fields(handle),
  androidHeapPrintMethods: (handle: string): Promise<string[]> => heap.methods(handle),

  // android intents
  androidIntentStartActivity: (activityClass: string): Promise<void> => intent.startActivity(activityClass),
  androidIntentStartService: (serviceClass: string): Promise<void> => intent.startService(serviceClass),

  // android keystore
  androidKeystoreClear: () => keystore.clear(),
  androidKeystoreList: (): Promise<IKeyStoreEntry[]> => keystore.list(),

  // android ssl pinning
  androidSslPinningDisable: (quiet: boolean) => sslpinning.disable(quiet),

  // android root detection
  androidRootDetectionDisable: () => root.disable(),
  androidRootDetectionEnable: () => root.enable(),

  // android user interface
  androidUiScreenshot: () => userinterface.screenshot(),
  androidUiSetFlagSecure: (v: boolean): Promise<void> => userinterface.setFlagSecure(v),
};
