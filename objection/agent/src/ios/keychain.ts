// dumps all of the keychain items available to the current
// application.
import { data_to_string } from "../lib/ios/helpers"
import { kSec } from "../lib/ios/constants"
import { KeychainItem } from "../lib/ios/interfaces"
import {
    SecItemCopyMatching,
    SecAccessControlGetConstraints,
    SecItemDelete,
    kCFBooleanTrue,
    NSDictionary,
} from "../lib/ios/libios"

const { NSMutableDictionary, NSString } = ObjC.classes;

// keychain item times to query for
const item_classes = [
    kSec.kSecClassKey,
    kSec.kSecClassIdentity,
    kSec.kSecClassCertificate,
    kSec.kSecClassGenericPassword,
    kSec.kSecClassInternetPassword
];

// class to interface with the iOS Keychain.
export class IosKeychain {

    empty() {

        // the base query dictionary to use for the keychain lookups
        const search_dictionary = NSMutableDictionary.alloc().init();

        item_classes.forEach(item_class => {

            // set the class-type we are querying for now
            search_dictionary.setObject_forKey_(item_class, kSec.kSecClass);

            // delete the classes items.
            SecItemDelete(search_dictionary);
        });
    }

    // dump the contents of the iOS keychain, returning the
    // results as an array representation.
    list(): Array<KeychainItem> {

        // the base query dictionary to use for the keychain lookups
        const search_dictionary = NSMutableDictionary.alloc().init();
        search_dictionary.setObject_forKey_(kCFBooleanTrue, kSec.kSecReturnAttributes);
        search_dictionary.setObject_forKey_(kCFBooleanTrue, kSec.kSecReturnData);
        search_dictionary.setObject_forKey_(kCFBooleanTrue, kSec.kSecReturnRef);
        search_dictionary.setObject_forKey_(kSec.kSecMatchLimitAll, kSec.kSecMatchLimit);

        let key_chain_items: Array<KeychainItem> = [].concat.apply([], item_classes.map(item_class => {

            let item_class_items: Array<KeychainItem> = [];

            search_dictionary.setObject_forKey_(item_class, kSec.kSecClass);

            // prepare a pointer for the results and call SecItemCopyMatching
            let results_pointer: NativePointer = Memory.alloc(Process.pointerSize);
            let copy_results: NativePointer = SecItemCopyMatching(search_dictionary, results_pointer);

            // without results (aka non-zero OSStatus) we just move along.
            if (!copy_results.isNull()) { return; }

            // read the resultant dict of the lookup from memory
            let search_results: NSDictionary = new ObjC.Object(Memory.readPointer(results_pointer));

            // if the results in the dict is empty (which is not something I expect),
            // fail fast too.
            if (search_results.length <= 0) { return; }

            // read each key chain entry for the current item_class and populate
            // the item_class items we will return
            for (let i: number = 0; i < search_results.count(); i++) {

                let data: NSDictionary = search_results.objectAtIndex_(i);

                item_class_items.push({
                    item_class: item_class,
                    create_date: data_to_string(data.objectForKey_(kSec.kSecAttrCreationDate)),
                    modification_date: data_to_string(data.objectForKey_(kSec.kSecAttrModificationDate)),
                    description: data_to_string(data.objectForKey_(kSec.kSecAttrDescription)),
                    comment: data_to_string(data.objectForKey_(kSec.kSecAttrComment)),
                    creator: data_to_string(data.objectForKey_(kSec.kSecAttrCreator)),
                    type: data_to_string(data.objectForKey_(kSec.kSecAttrType)),
                    script_code: data_to_string(data.objectForKey_(kSec.kSecAttrScriptCode)),
                    alias: data_to_string(data.objectForKey_(kSec.kSecAttrAlias)),
                    invisible: data_to_string(data.objectForKey_(kSec.kSecAttrIsInvisible)),
                    negative: data_to_string(data.objectForKey_(kSec.kSecAttrIsNegative)),
                    custom_icon: data_to_string(data.objectForKey_(kSec.kSecAttrHasCustomIcon)),
                    protected: data_to_string(data.objectForKey_(kSec.kSecProtectedDataItemAttr)),
                    access_control: (data.containsKey_(kSec.kSecAttrAccessControl)) ? this.decode_acl(data) : '',
                    accessible_attribute: kSec[data.objectForKey_(kSec.kSecAttrAccessible)],
                    entitlement_group: data_to_string(data.objectForKey_(kSec.kSecAttrAccessGroup)),
                    generic: data_to_string(data.objectForKey_(kSec.kSecAttrGeneric)),
                    service: data_to_string(data.objectForKey_(kSec.kSecAttrService)),
                    account: data_to_string(data.objectForKey_(kSec.kSecAttrAccount)),
                    label: data_to_string(data.objectForKey_(kSec.kSecAttrLabel)),
                    data: data_to_string(data.objectForKey_(kSec.kSecValueData)),
                });
            }

            return item_class_items;

        }).filter(n => n != undefined));

        return key_chain_items;
    }

    // decode the access control attributes on a keychain
    // entry into a human readable string. Getting an idea of what the
    // constriants actually are is done using an undocumented method,
    // SecAccessControlGetConstraints.
    private decode_acl(entry: NSDictionary): string {

        const access_controls = new ObjC.Object(
            SecAccessControlGetConstraints(entry.objectForKey_(kSec.kSecAttrAccessControl)));

        // Ensure we were able to get the SecAccessControlRef
        if (access_controls.handle.isNull()) { return ''; }

        let flags: Array<string> = [];
        var access_control_enumerator: NSDictionary = access_controls.keyEnumerator();
        let access_control_item_key: any;

        while ((access_control_item_key = access_control_enumerator.nextObject()) !== null) {

            let access_control_item: NSDictionary = access_controls.objectForKey_(access_control_item_key);

            switch (data_to_string(access_control_item_key)) {

                // Defaults?
                case 'dacl':
                    break;

                case 'osgn':
                    flags.push('kSecAttrKeyClassPrivate');

                case 'od':
                    let constraints: NSDictionary = access_control_item;
                    let constraint_enumerator = constraints.keyEnumerator();
                    let constraint_item_key;

                    while ((constraint_item_key = constraint_enumerator.nextObject()) !== null) {

                        switch (data_to_string(constraint_item_key)) {
                            case 'cpo':
                                flags.push('kSecAccessControlUserPresence');
                                break;

                            case 'cup':
                                flags.push('kSecAccessControlDevicePasscode');
                                break;

                            case 'pkofn':
                                constraints.objectForKey_('pkofn') == 1 ?
                                    flags.push('Or') :
                                    flags.push('And');
                                break;

                            case 'cbio':
                                constraints.objectForKey_('cbio').count() == 1 ?
                                    flags.push('kSecAccessControlBiometryAny') :
                                    flags.push('kSecAccessControlBiometryCurrentSet');
                                break;

                            default:
                                break;
                        }
                    }

                    break;

                case 'prp':
                    flags.push('kSecAccessControlApplicationPassword');
                    break;

                default:
                    break;
            }
        }

        return '';
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

//         NSString *stringRes = [[NSString alloc] initWithData:[entry objectForKey:@"v_Data"] encoding:NSUTF8StringEncoding];
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

