// Provides methods to work with process memory.

// Originally part of Frida <=11 but got removed in 12.
// https://github.com/frida/frida-python/commit/72899a4315998289fb171149d62477ba7d1fcb91

rpc.exports = {

    enumerateRanges: function (protection) {
        return Process.enumerateRangesSync(protection);
    },
    readBytes: function (address, size) {
        return Memory.readByteArray(ptr(address), size);
    },
}
