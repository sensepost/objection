import * as m from "../generic/memory";

export const memory = {

  memoryDump: (address: string, size: number) => m.dump(address, size),
  memoryListExports: (name: string): ModuleExportDetails[] => m.listExports(name),
  memoryListModules: (): Module[] => m.listModules(),
  memoryListRanges: (protection: string): RangeDetails[] => m.listRanges(protection),
  memorySearch: (pattern: string, onlyOffsets: boolean): string[] => m.search(pattern, onlyOffsets),
  memoryReplace: (pattern: string, replace: number[]): string[] => m.replace(pattern, replace),
  memoryWrite: (address: string, value: number[]): void => m.write(address, value),

};
