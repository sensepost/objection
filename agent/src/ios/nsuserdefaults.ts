import { ObjC } from "../ios/lib/libobjc.js";
import {
  NSDictionary,
  NSUserDefaults
} from "./lib/types.js";


export const get = (): NSUserDefaults | any => {
  // -- Sample Objective-C
  //
  // NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
  // NSLog(@"%@", [d dictionaryRepresentation]);

  const defaults: NSUserDefaults = ObjC.classes.NSUserDefaults.standardUserDefaults();
  const data: NSDictionary = defaults.dictionaryRepresentation();

  return data.toString();
};

export const set = (key: string, value: any, valueType?: string): boolean => {
  // -- Sample Objective-C
  //
  // NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
  // [d setObject:value forKey:key];
  // [d synchronize];

  const defaults: NSUserDefaults = ObjC.classes.NSUserDefaults.standardUserDefaults();

  // Determine type and set accordingly
  if (valueType === "bool") {
    defaults.setBool_forKey_(value, key);
  } else if (valueType === "int") {
    defaults.setInteger_forKey_(value, key);
  } else if (valueType === "float") {
    defaults.setDouble_forKey_(value, key);
  } else {
    // Default to string/object
    defaults.setObject_forKey_(value, key);
  }

  // Persist to disk
  defaults.synchronize();

  return true;
};
