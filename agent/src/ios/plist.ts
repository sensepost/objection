import ObjC from "frida-objc-bridge";
import { NSMutableDictionary } from "./lib/types.js";


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
