import { colors } from "../lib/color";

export namespace memory {

  export const listModules = (): Module[] => {
    return Process.enumerateModules();
  };

  export const listExports = (name: string): ModuleExportDetails[] | null => {
    const mod: Module[] = Process.enumerateModules().filter((m) => m.name === name);
    if (mod.length <= 0) {
      return null;
    }
    return mod[0].enumerateExports();
  };

  export const listRanges = (protection: string = "rw-"): RangeDetails[] => {
    return Process.enumerateRanges(protection);
  };

  export const dump = (address: string, size: number): ArrayBuffer => {
    // Originally part of Frida <=11 but got removed in 12.
    // https://github.com/frida/frida-python/commit/72899a4315998289fb171149d62477ba7d1fcb91
    return new NativePointer(address).readByteArray(size);
  };

  export const search = (pattern: string, onlyOffsets: boolean = false): string[] => {
    const addresses = listRanges("rw-")
      .map((range) => {
        return Memory.scanSync(range.base, range.size, pattern)
          .map((match) => {
            if (!onlyOffsets) {
              colors.log(hexdump(match.address, {
                ansi: true,
                header: false,
                length: 48,
              }));
            }
            return match.address.toString();
          });
      });

    return [].concat.apply([], addresses);
  };

  export const write = (address: string, value: number[]): void => {
    new NativePointer(address).writeByteArray(value);
  };
}
