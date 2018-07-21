// dumps all of the keychain items available to the current
// application.
import { kSec } from "../lib/ios/constants";
import { data_to_string } from "../lib/ios/helpers";
import { IKeychainItem } from "../lib/ios/interfaces";
import {
    libObjc,
    NSDictionary,
    NSMutableDictionary,
    NSString,
 } from "../lib/ios/libobjc";

const { NSMutableDictionary, NSString } = ObjC.classes;
const NSUTF8StringEncoding = 4;

// keychain item times to query for
const itemClasses = [
    kSec.kSecClassKey,
    kSec.kSecClassIdentity,
    kSec.kSecClassCertificate,
    kSec.kSecClassGenericPassword,
    kSec.kSecClassInternetPassword,
];

// class to interface with the iOS Keychain.
export class IosKeychain {

    // clean out the keychain
    public empty() {

        const searchDictionary = NSMutableDictionary.alloc().init();

        itemClasses.forEach((clazz) => {

            // set the class-type we are querying for now & delete
            searchDictionary.setObject_forKey_(clazz, kSec.kSecClass);
            libObjc.SecItemDelete(searchDictionary);
        });
    }

    // dump the contents of the iOS keychain, returning the
    // results as an array representation.
    public list(): IKeychainItem[] {

        const kCFBooleanTrue = ObjC.classes.__NSCFBoolean.numberWithBool_(true);

        // the base query dictionary to use for the keychain lookups
        const searchDictionary = NSMutableDictionary.alloc().init();
        searchDictionary.setObject_forKey_(kCFBooleanTrue, kSec.kSecReturnAttributes);
        searchDictionary.setObject_forKey_(kCFBooleanTrue, kSec.kSecReturnData);
        searchDictionary.setObject_forKey_(kCFBooleanTrue, kSec.kSecReturnRef);
        searchDictionary.setObject_forKey_(kSec.kSecMatchLimitAll, kSec.kSecMatchLimit);

        const kcItems: IKeychainItem[] = [].concat.apply([], itemClasses.map((clazz) => {

            const clazzItems: IKeychainItem[] = [];

            searchDictionary.setObject_forKey_(clazz, kSec.kSecClass);

            // prepare a pointer for the results and call SecItemCopyMatching to get them
            const resultsPointer: NativePointer = Memory.alloc(Process.pointerSize);
            // const copyResult: NativePointer = SecItemCopyMatching(searchDictionary, resultsPointer);
            const copyResult: NativePointer = libObjc.SecItemCopyMatching(searchDictionary, resultsPointer);

            // without results (aka non-zero OSStatus) we just move along.
            if (!copyResult.isNull()) { return; }

            // read the resultant dict of the lookup from memory
            const searchResults: NSDictionary = new ObjC.Object(Memory.readPointer(resultsPointer));

            // if the results in the dict is empty (which is not something I expect),
            // fail fast too.
            if (searchResults.length <= 0) { return; }

            // read each key chain entry for the current item_class and populate
            // the item_class items we will return
            for (let i: number = 0; i < searchResults.count(); i++) {

                const data: NSDictionary = searchResults.objectAtIndex_(i);

                clazzItems.push({
                    access_control: (data.containsKey_(kSec.kSecAttrAccessControl)) ? this.decode_acl(data) : "",
                    accessible_attribute: kSec[data.objectForKey_(kSec.kSecAttrAccessible)],
                    account: data_to_string(data.objectForKey_(kSec.kSecAttrAccount)),
                    alias: data_to_string(data.objectForKey_(kSec.kSecAttrAlias)),
                    comment: data_to_string(data.objectForKey_(kSec.kSecAttrComment)),
                    create_date: data_to_string(data.objectForKey_(kSec.kSecAttrCreationDate)),
                    creator: data_to_string(data.objectForKey_(kSec.kSecAttrCreator)),
                    custom_icon: data_to_string(data.objectForKey_(kSec.kSecAttrHasCustomIcon)),
                    data: data_to_string(data.objectForKey_(kSec.kSecValueData)),
                    description: data_to_string(data.objectForKey_(kSec.kSecAttrDescription)),
                    entitlement_group: data_to_string(data.objectForKey_(kSec.kSecAttrAccessGroup)),
                    generic: data_to_string(data.objectForKey_(kSec.kSecAttrGeneric)),
                    invisible: data_to_string(data.objectForKey_(kSec.kSecAttrIsInvisible)),
                    item_class: clazz,
                    label: data_to_string(data.objectForKey_(kSec.kSecAttrLabel)),
                    modification_date: data_to_string(data.objectForKey_(kSec.kSecAttrModificationDate)),
                    negative: data_to_string(data.objectForKey_(kSec.kSecAttrIsNegative)),
                    protected: data_to_string(data.objectForKey_(kSec.kSecProtectedDataItemAttr)),
                    script_code: data_to_string(data.objectForKey_(kSec.kSecAttrScriptCode)),
                    service: data_to_string(data.objectForKey_(kSec.kSecAttrService)),
                    type: data_to_string(data.objectForKey_(kSec.kSecAttrType)),
                });
            }

            return clazzItems;

        }).filter((n) => n !== undefined));

        return kcItems;
    }

    // add a string entry to the keychain
    public add(key: string, data: string): boolean {

        // Convert the key and data to NSData
        const dataString: NSString = NSString.stringWithString_(data).dataUsingEncoding_(NSUTF8StringEncoding);
        const dataKey: NSString = NSString.stringWithString_(key).dataUsingEncoding_(NSUTF8StringEncoding);

        const itemDict: NSMutableDictionary = NSMutableDictionary.alloc().init();

        itemDict.setObject_forKey_(kSec.kSecClassGenericPassword, kSec.kSecClass);
        itemDict.setObject_forKey_(dataKey, kSec.kSecAttrService);
        itemDict.setObject_forKey_(dataString, kSec.kSecValueData);

        // Add the keychain entry
        const result: any = libObjc.SecItemAdd(itemDict, NULL);

        if (result !== 0x00) { return false; }

        return true;
    }

    // decode the access control attributes on a keychain
    // entry into a human readable string. Getting an idea of what the
    // constriants actually are is done using an undocumented method,
    // SecAccessControlGetConstraints.
    private decode_acl(entry: NSDictionary): string {

        const acl = new ObjC.Object(
            libObjc.SecAccessControlGetConstraints(entry.objectForKey_(kSec.kSecAttrAccessControl)));

        // Ensure we were able to get the SecAccessControlRef
        if (acl.handle.isNull()) { return ""; }

        const flags: string[] = [];
        const aclEnum: NSDictionary = acl.keyEnumerator();
        let aclItemkey: any;

        // tslint:disable-next-line:no-conditional-assignment
        while ((aclItemkey = aclEnum.nextObject()) !== null) {

            const aclItem: NSDictionary = acl.objectForKey_(aclItemkey);

            switch (data_to_string(aclItemkey)) {

                // Defaults?
                case "dacl":
                    break;

                case "osgn":
                    flags.push("kSecAttrKeyClassPrivate");

                case "od":
                    const constraints: NSDictionary = aclItem;
                    const constraintEnum = constraints.keyEnumerator();
                    let constraintItemKey;

                    // tslint:disable-next-line:no-conditional-assignment
                    while ((constraintItemKey = constraintEnum.nextObject()) !== null) {

                        switch (data_to_string(constraintItemKey)) {
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
                                constraints.objectForKey_("cbio").count() === 1 ?
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

        return "";
    }
}

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

// To reference some of the constants, the had to be echoed to
// get their values.

// NSLog(@"Constants Dump");
// NSLog(@"kSecAttrService: %@", kSecAttrService);
// NSLog(@"End Constants Dump");
