import { NSMutableDictionary } from "./lib/types";

export namespace plist {

  export const read = (path: string): string => {
    // -- Sample Objective-C
    //
    // NSMutableDictionary *result = [[NSMutableDictionary alloc] initWithContentsOfFile:path];

    const dictionary: NSMutableDictionary = ObjC.classes.NSMutableDictionary;
    return dictionary.alloc().initWithContentsOfFile_(path).toString();
  };

  export const write = (path: string, data: any): void => {
    // TODO
  };
}
