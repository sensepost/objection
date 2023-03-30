// dumps all of the keychain items available to the current
// application.
import { colors as c } from "../lib/color";
import { reverseEnumLookup } from "../lib/helpers";
import {
  kSec,
  NSUTF8StringEncoding
} from "./lib/constants";
import {
  bytesToHexString,
  bytesToUTF8,
  smartDataToString
} from "./lib/helpers";
import {
  IKeychainData,
  IKeychainItem
} from "./lib/interfaces";
import { libObjc } from "./lib/libobjc";
import {
  NSDictionary,
  NSMutableDictionary as NSMutableDictionaryType,
  NSString as NSStringType,
} from "./lib/types";

// keychain item times to query for
const itemClasses = [
  kSec.kSecClassKey,
  kSec.kSecClassIdentity,
  kSec.kSecClassCertificate,
  kSec.kSecClassGenericPassword,
  kSec.kSecClassInternetPassword,
];


// The parent method that enumerates the iOS keychain
const enumerateKeychain = (): IKeychainData[] => {
  // -- Sample Objective-C
  //
  // NSMutableDictionary *query = [[NSMutableDictionary alloc] init];
  // [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnAttributes];
  // [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
  // [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnRef];
  // [query setObject:(__bridge id)kSecMatchLimitAll forKey:(__bridge id)kSecMatchLimit];
  // NSArray *itemClasses = [NSArray arrayWithObjects:
  //                         (__bridge id)kSecClassKey,
  //                         (__bridge id)kSecClassIdentity,
  //                         (__bridge id)kSecClassCertificate,
  //                         (__bridge id)kSecClassGenericPassword,
  //                         (__bridge id)kSecClassInternetPassword,
  //                         nil];
  // for (id itemClass in itemClasses) {
  //     NSLog(@"Querying: %@", itemClass);
  //     [query setObject:itemClass forKey:(__bridge id)kSecClass];
  //     CFTypeRef result = NULL;
  //     OSStatus findStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
  //     if(findStatus != errSecSuccess) {
  //         NSLog(@"Failed to query keychain for types %@", itemClass);
  //         continue;
  //     }
  //     // loopy-loop the results
  //     for (NSDictionary *entry in (__bridge NSDictionary *)result) {
  //         NSString *stringRes = [[NSString alloc] initWithData:[entry objectForKey:@"v_Data"]
  //                                                     encoding:NSUTF8StringEncoding];
  //         NSLog(@"%@", stringRes);
  //     }
  //     if (result != NULL) {
  //         CFRelease(result);
  //     }
  // }

  // http://nshipster.com/bool/
  const kCFBooleanTrue = ObjC.classes.__NSCFBoolean.numberWithBool_(true);

  // the base query dictionary to use for the keychain lookups
  const searchDictionary: NSMutableDictionaryType = ObjC.classes.NSMutableDictionary.alloc().init();
  searchDictionary.setObject_forKey_(kCFBooleanTrue, kSec.kSecReturnAttributes);
  searchDictionary.setObject_forKey_(kCFBooleanTrue, kSec.kSecReturnData);
  searchDictionary.setObject_forKey_(kCFBooleanTrue, kSec.kSecReturnRef);
  searchDictionary.setObject_forKey_(kSec.kSecMatchLimitAll, kSec.kSecMatchLimit);
  searchDictionary.setObject_forKey_(kSec.kSecAttrSynchronizableAny, kSec.kSecAttrSynchronizable);

  // loop each of the keychain class types and extract data
  const itemClassResults: IKeychainData[][] = itemClasses.map((clazz) => {
    const data: IKeychainData[] = [];  // start empty.
    searchDictionary.setObject_forKey_(clazz, kSec.kSecClass);

    // prepare a pointer for the results and call SecItemCopyMatching to get them
    const resultsPointer: NativePointer = Memory.alloc(Process.pointerSize);
    const copyResult: NativePointer = libObjc.SecItemCopyMatching(searchDictionary, resultsPointer);

    // without results (aka non-zero OSStatus) we just move along.
    if (!copyResult.isNull()) { return data; }

    // read the resultant dict of the lookup from memory
    const searchResults: NSDictionary = new ObjC.Object(resultsPointer.readPointer());

    // if the results in the dict is empty (which is not something I expect),
    // fail fast too.
    if (searchResults.length <= 0) { return data; }

    // read each key chain entry for the current item_class and populate
    // the item_class items we will return
    for (let i: number = 0; i < searchResults.count(); i++) {
      data.push({
        clazz,
        data: searchResults.objectAtIndex_(i),
      });
    }

    return data;
  });

  return [].concat(...itemClassResults).filter((n) => n !== undefined);
};

// print raw entries using some Frida magic
// to do the toString() repr...
export const listRaw = (): void => {
  enumerateKeychain().forEach((e) => {
    c.log(e.data);
  });
};

// dump the contents of the iOS keychain, returning the
// results as an array representation.
export const list = (smartDecode: boolean = false): IKeychainItem[] => {
  return enumerateKeychain().map((entry) => {
    const { data, clazz } = entry;
    return {
      access_control: (data.containsKey_(kSec.kSecAttrAccessControl)) ? decodeAcl(data) : "",
      accessible_attribute: reverseEnumLookup(kSec,
        bytesToUTF8(data.objectForKey_(kSec.kSecAttrAccessible))),
      account: bytesToUTF8(data.objectForKey_(kSec.kSecAttrAccount)),
      alias: bytesToUTF8(data.objectForKey_(kSec.kSecAttrAlias)),
      comment: bytesToUTF8(data.objectForKey_(kSec.kSecAttrComment)),
      create_date: bytesToUTF8(data.objectForKey_(kSec.kSecAttrCreationDate)),
      creator: bytesToUTF8(data.objectForKey_(kSec.kSecAttrCreator)),
      custom_icon: bytesToUTF8(data.objectForKey_(kSec.kSecAttrHasCustomIcon)),
      data: (clazz !== "keys") ?
        (smartDecode) ?
          smartDataToString(data.objectForKey_(kSec.kSecValueData)) :
          bytesToUTF8(data.objectForKey_(kSec.kSecValueData)) :
        "(Key data not displayed)",
      dataHex: bytesToHexString(data.objectForKey_(kSec.kSecValueData)),
      description: bytesToUTF8(data.objectForKey_(kSec.kSecAttrDescription)),
      entitlement_group: bytesToUTF8(data.objectForKey_(kSec.kSecAttrAccessGroup)),
      generic: bytesToUTF8(data.objectForKey_(kSec.kSecAttrGeneric)),
      invisible: bytesToUTF8(data.objectForKey_(kSec.kSecAttrIsInvisible)),
      item_class: reverseEnumLookup(kSec, clazz),
      label: bytesToUTF8(data.objectForKey_(kSec.kSecAttrLabel)),
      modification_date: bytesToUTF8(data.objectForKey_(kSec.kSecAttrModificationDate)),
      negative: bytesToUTF8(data.objectForKey_(kSec.kSecAttrIsNegative)),
      protected: bytesToUTF8(data.objectForKey_(kSec.kSecProtectedDataItemAttr)),
      script_code: bytesToUTF8(data.objectForKey_(kSec.kSecAttrScriptCode)),
      service: bytesToUTF8(data.objectForKey_(kSec.kSecAttrService)),
      type: bytesToUTF8(data.objectForKey_(kSec.kSecAttrType)),
    };
  });
};

// clean out the keychain
export const empty = (): void => {
  const searchDictionary: NSMutableDictionaryType = ObjC.classes.NSMutableDictionary.alloc().init();
  searchDictionary.setObject_forKey_(kSec.kSecAttrSynchronizableAny, kSec.kSecAttrSynchronizable);
  itemClasses.forEach((clazz) => {

    // set the class-type we are querying for now & delete
    searchDictionary.setObject_forKey_(clazz, kSec.kSecClass);
    libObjc.SecItemDelete(searchDictionary);
  });
};

// add a string entry to the keychain
export const add = (account: string, service: string, data: string): boolean => {

  // prepare the dictionary for SecItemAdd()
  const itemDict: NSMutableDictionaryType = ObjC.classes.NSMutableDictionary.alloc().init();
  itemDict.setObject_forKey_(kSec.kSecClassGenericPassword, kSec.kSecClass);

  [
    { "type": "account", "value": account, "ksec": kSec.kSecAttrAccount },
    { "type": "service", "value": service, "ksec": kSec.kSecAttrService },
    { "type": "data", "value": data, "ksec": kSec.kSecValueData }
  ].forEach(e => {
    if (e.value == null) return;
    const v: NSStringType = ObjC.classes.NSString.stringWithString_(e.value)
      .dataUsingEncoding_(NSUTF8StringEncoding);

    itemDict.setObject_forKey_(v, e.ksec);
  });

  // Add the keychain entry
  const result: any = libObjc.SecItemAdd(itemDict, NULL);
  return result.isNull();
};

// decode the access control attributes on a keychain
// entry into a human readable string. Getting an idea of what the
// constraints actually are is done using an undocumented method,
// SecAccessControlGetConstraints.
const decodeAcl = (entry: NSDictionary): string => {
  const acl = new ObjC.Object(
    libObjc.SecAccessControlGetConstraints(entry.objectForKey_(kSec.kSecAttrAccessControl)));

  // Ensure we were able to get the SecAccessControlRef
  if (acl.handle.isNull()) { return "None"; }

  const flags: string[] = [];
  const aclEnum: NSDictionary = acl.keyEnumerator();
  let aclItemkey: any;

  // tslint:disable-next-line:no-conditional-assignment
  while ((aclItemkey = aclEnum.nextObject()) !== null) {
    const aclItem: NSDictionary = acl.objectForKey_(aclItemkey);

    switch (smartDataToString(aclItemkey)) {

      // Defaults?
      case "dacl":
        break;

      case "osgn":
        flags.push("kSecAttrKeyClassPrivate");
        break;

      case "od":
        const constraints: NSDictionary = aclItem;
        const constraintEnum = constraints.keyEnumerator();
        let constraintItemKey;

        // tslint:disable-next-line:no-conditional-assignment
        while ((constraintItemKey = constraintEnum.nextObject()) !== null) {

          switch (smartDataToString(constraintItemKey)) {
            case "cpo":
              flags.push("kSecAccessControlUserPresence");
              break;

            case "cup":
              flags.push("kSecAccessControlDevicePasscode");
              break;

            case "pkofn":
              constraints.objectForKey_("pkofn") === 1 ?
                flags.push("Or") :
                flags.push("And");
              break;

            case "cbio":
              constraints.objectForKey_("cbio").count().valueOf() === 1 ?
                flags.push("kSecAccessControlBiometryAny") :
                flags.push("kSecAccessControlBiometryCurrentSet");
              break;

            default:
              break;
          }
        }

        break;

      case "prp":
        flags.push("kSecAccessControlApplicationPassword");
        break;

      default:
        break;
    }
  }

  return flags.join(" ");
};
