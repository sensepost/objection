import { AndroidFilesystem } from "./android/filesystem";
import { environment } from "./generic/environment";
import { IosFilesystem } from "./ios/filesystem";
import { IosJailBreak } from "./ios/jailbreak";
import { IosKeychain } from "./ios/keychain";
import { nsuserdefaults } from "./ios/nsuserdefaults";
import { Plist } from "./ios/plist";
import { Jobs } from "./lib/jobs";
import { version } from "./version";

const jobs: Jobs = new Jobs();

const keychain: IosKeychain = new IosKeychain();
const androidfilesystem: AndroidFilesystem = new AndroidFilesystem();
const iosfilesystem: IosFilesystem = new IosFilesystem();
const iosjailbreak: IosJailBreak = new IosJailBreak(jobs);
const plist: Plist = new Plist();

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

  // ios filesystem
  iosFileCwd: () => iosfilesystem.pwd(),
  iosFileDownload: (path: string) => iosfilesystem.readFile(path),
  iosFileExists: (path: string) => iosfilesystem.exists(path),
  iosFileLs: (path: string) => iosfilesystem.ls(path),
  iosFilePathIsFile: (path: string) => iosfilesystem.pathIsFile(path),
  iosFileReadable: (path: string) => iosfilesystem.readable(path),
  iosFileUpload: (path: string, data: string) => iosfilesystem.writeFile(path, data),
  iosFileWritable: (path: string) => iosfilesystem.writable(path),

  // jailbreak detection
  iosJailbreakDisable: () => iosjailbreak.disable(),

  // plist files
  iosPlistRead: (path: string) => plist.read(path),

  // keychain
  keychainAdd: (key: string, data: string) => keychain.add(key, data),
  keychainEmpty: () => keychain.empty(),
  keychainList: () => keychain.list(),

  // nsuserdefaults
  nsuserDefaults: () => nsuserdefaults(),

  // meta
  version: () => version,
};
