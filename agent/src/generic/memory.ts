export namespace memory {

  export const listModules = (): ModuleDetails[] => {
    return Process.enumerateModulesSync();
  };

  export const listExports = (module: string): ModuleExportDetails[] => {
    return Module.enumerateExportsSync(module);
  };

  export const listRanges = (protection: string = "rw-"): RangeDetails[] => {
    return Process.enumerateRangesSync(protection);
  };

  export const dump = (address: string, size: number): ArrayBuffer => {
    // Originally part of Frida <=11 but got removed in 12.
    // https://github.com/frida/frida-python/commit/72899a4315998289fb171149d62477ba7d1fcb91
    const addressPtr = new NativePointer(address);
    return Memory.readByteArray(addressPtr, size);
  };

  export const search = (pattern: string): string[] => {
    const addresses = listRanges("r--")
      .map((range) => {
        return Memory.scanSync(range.base, range.size, pattern)
          .map((match) => {
            return match.address.toString();
          });
      });

    return [].concat.apply([], addresses);
  };

  export const write = (address: string, value: number[]): void => {
    const addressPtr = new NativePointer(address);
    Memory.writeByteArray(addressPtr, value);
  };
}
