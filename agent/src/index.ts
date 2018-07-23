import { IosFilesystem } from "./ios/filesystem";
import { IosJailBreak } from "./ios/jailbreak";
import { IosKeychain } from "./ios/keychain";
import { nsuserdefaults} from "./ios/nsuserdefaults";
import { Plist } from "./ios/plist";
import { version } from "./version";

const keychain: IosKeychain = new IosKeychain();
const iosfilesystem: IosFilesystem = new IosFilesystem();
const iosjailbreak: IosJailBreak = new IosJailBreak();
const plist: Plist = new Plist();

rpc.exports = {

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
