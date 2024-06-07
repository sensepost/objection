import {
  NSDictionary,
  NSUserDefaults
} from "./lib/types.js";


export const get = (): NSUserDefaults | any => {
  // -- Sample Objective-C
  //
  // NSUserDefaults *d = [[NSUserDefaults alloc] init];
  // NSLog(@"%@", [d dictionaryRepresentation]);

  const defaults: NSUserDefaults = ObjC.classes.NSUserDefaults;
  const data: NSDictionary = defaults.alloc().init().dictionaryRepresentation();

  return data.toString();
};
