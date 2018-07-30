import { NSMutableDictionary } from "../lib/ios/types";

export class Plist {

  public read(path: string): NSMutableDictionary {
    const dictionary: NSMutableDictionary = ObjC.classes.NSMutableDictionary;

    return dictionary.alloc().initWithContentsOfFile_(path);
  }

  public write(path: string, data: any): void {
    // TODO
  }
}
