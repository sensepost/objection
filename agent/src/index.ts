import { IosKeychain } from "./ios/keychain";
import { version } from "./version";

const keychain: IosKeychain = new IosKeychain();

rpc.exports = {

    // keychain
    keychainAdd: (key: string, data: string) => keychain.add(key, data),
    keychainEmpty: () => keychain.empty(),
    keychainList: () => keychain.list(),

    // meta
    version: () => version,
};
