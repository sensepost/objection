import { NSDictionary, NSUserDefaults } from "./lib/types";

export namespace nsuserdefaults {

  export const get = (): NSUserDefaults | any => {
    // -- Sample Objective-C
    //
    // NSUserDefaults *d = [[NSUserDefaults alloc] init];
    // NSLog(@"%@", [d dictionaryRepresentation]);

    const defauts: NSUserDefaults = ObjC.classes.NSUserDefaults;
    const data: NSDictionary = defauts.alloc().init().dictionaryRepresentation();

    return data.toString();
  };
}
