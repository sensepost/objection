import { IosKeychain } from "./ios/keychain";

const keychain = new IosKeychain();

rpc.exports = {
    keychainAdd: () => keychain.add.bind(keychain),
    keychainDump: () => keychain.list.bind(keychain),
    keychainEmpty: () => keychain.empty.bind(keychain),
};
