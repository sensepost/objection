import { IosFilesystem } from "./ios/filesystem";
import { IosJailBreak } from "./ios/jailbreak";
import { IosKeychain } from "./ios/keychain";
import { nsuserdefaults} from "./ios/nsuserdefaults";
import { Plist } from "./ios/plist";
import { Environment } from "./lib/environment";
import { Jobs } from "./lib/jobs";
import { version } from "./version";

const jobs: Jobs = new Jobs();
const environment: Environment = new Environment();

const keychain: IosKeychain = new IosKeychain();
const iosfilesystem: IosFilesystem = new IosFilesystem();
const iosjailbreak: IosJailBreak = new IosJailBreak();
const plist: Plist = new Plist();

rpc.exports = {

    // environment
    envAndroid: () => environment.androidPackage(),
    envAndroidPaths: () => environment.androidPaths(),
    envFrida: () => environment.frida(),
    envIos: () => environment.iosPackage(),
    envIosPaths: () => environment.iosPaths(),
    envRuntime: () => environment.runtime(),

    // ios filesystem
    iosLs: (path: string) => iosfilesystem.ls(path),
    iosRead: (path: string) => iosfilesystem.getFile(path),

    // jailbreak detection
    iosJailbreakDisable: () => iosjailbreak.disable(),

    // plist files
    iosPlistRead: (path: string) => plist.read(path),

    // keychain
    keychainAdd: (key: string, data: string) => keychain.add(key, data),
    keychainEmpty: () => keychain.empty(),
    keychainList: () => keychain.list(),

    nsuserDefaults: () => nsuserdefaults(),

    // meta
    version: () => version,
};
