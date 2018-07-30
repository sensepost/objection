import { NSDictionary, NSUserDefaults } from "./lib/types";

export let nsuserdefaults: NSUserDefaults | any = () => {

  const defauts: NSUserDefaults = ObjC.classes.NSUserDefaults;
  const data: NSDictionary = defauts.alloc().init().dictionaryRepresentation();

  return data.toString();
};

// -- Sample Objective-C
//
// NSUserDefaults *d = [[NSUserDefaults alloc] init];
// NSLog(@"%@", [d dictionaryRepresentation]);
