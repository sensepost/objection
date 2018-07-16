import { IosKeychain } from "./ios/keychain"

rpc.exports = {
    keychainDump: () => (new IosKeychain).list(),
    keychainEmpty: () => (new IosKeychain).empty(),
}
