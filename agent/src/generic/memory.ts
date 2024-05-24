import { colors } from "../lib/color.js"

export const listModules = (): Module[] => {
  return Process.enumerateModules();
};

export const listExports = (name: string): ModuleExportDetails[] => {
  const mod: Module[] = Process.enumerateModules().filter((m) => m.name === name);
  if (mod.length <= 0) {
    return [];
  }
  return mod[0].enumerateExports();
};

export const listRanges = (protection: string = "rw-"): RangeDetails[] => {
  return Process.enumerateRanges(protection);
};

export const dump = (address: string, size: number): ArrayBuffer => {
  // Originally part of Frida <=11 but got removed in 12.
  // https://github.com/frida/frida-python/commit/72899a4315998289fb171149d62477ba7d1fcb91
  const data = new NativePointer(address).readByteArray(size);
  if (data) {
    return data;
  }
  else {
    return new ArrayBuffer(0);
  }
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
    }).filter((m) => m.length !== 0);

  if (addresses.length <= 0) {
    return [];
  }

  return addresses.reduce((a, b) => a.concat(b));
};

export const replace = (pattern: string, replace: number[]): string[] => {  
  return search(pattern, true).map((match) => {
    write(match, replace);
    return match;
  })
};

export const write = (address: string, value: number[]): void => {
  new NativePointer(address).writeByteArray(value);
};
