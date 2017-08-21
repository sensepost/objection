// Dumps all of the keychain items available to the current
// application.

var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
var NSArray = ObjC.classes.NSArray;
var NSString = ObjC.classes.NSString;
var NSKeyedUnarchiver = ObjC.classes.NSKeyedUnarchiver;

// Ref: http://nshipster.com/bool/
var kCFBooleanTrue = ObjC.classes.__NSCFBoolean.numberWithBool_(true);
var SecItemCopyMatching = new NativeFunction(
    ptr(Module.findExportByName('Security', 'SecItemCopyMatching')), 'pointer', ['pointer', 'pointer']);

// constants
var kSecReturnAttributes = 'r_Attributes',
    kSecReturnData = 'r_Data',
    kSecReturnRef = 'r_Ref',
    kSecMatchLimit = 'm_Limit',
    kSecMatchLimitAll = 'm_LimitAll',
    kSecClass = 'class',
    kSecClassKey = 'keys',
    kSecClassIdentity = 'idnt',
    kSecClassCertificate = 'cert',
    kSecClassGenericPassword = 'genp',
    kSecClassInternetPassword = 'inet',
    kSecAttrService = 'svce',
    kSecAttrAccount = 'acct',
    kSecAttrAccessGroup = 'agrp',
    kSecAttrLabel = 'labl',
    kSecAttrCreationDate = 'cdat',
    kSecAttrAccessControl = 'accc',
    kSecAttrGeneric = 'gena',
    kSecAttrSynchronizable = 'sync',
    kSecAttrModificationDate = 'mdat',
    kSecAttrServer = 'srvr',
    kSecAttrDescription = 'desc',
    kSecAttrComment = 'icmt',
    kSecAttrCreator = 'crtr',
    kSecAttrType = 'type',
    kSecAttrScriptCode = 'scrp',
    kSecAttrAlias = 'alis',
    kSecAttrIsInvisible = 'invi',
    kSecAttrIsNegative = 'nega',
    kSecAttrHasCustomIcon = 'cusi',
    kSecProtectedDataItemAttr = 'prot',
    kSecAttrAccessible = 'pdmn',
    kSecAttrAccessibleWhenUnlocked = 'ak',
    kSecAttrAccessibleAfterFirstUnlock = 'ck',
    kSecAttrAccessibleAlways = 'dk',
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly = 'aku',
    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = 'cku',
    kSecAttrAccessibleAlwaysThisDeviceOnly = 'dku';

// dict for reverse constants lookups
var kSecConstantReverse = {
    'r_Attributes': 'kSecReturnAttributes',
    'r_Data': 'kSecReturnData',
    'r_Ref': 'kSecReturnRef',
    'm_Limit': 'kSecMatchLimit',
    'm_LimitAll': 'kSecMatchLimitAll',
    'class': 'kSecClass',
    'keys': 'kSecClassKey',
    'idnt': 'kSecClassIdentity',
    'cert': 'kSecClassCertificate',
    'genp': 'kSecClassGenericPassword',
    'inet': 'kSecClassInternetPassword',
    'svce': 'kSecAttrService',
    'acct': 'kSecAttrAccount',
    'agrp': 'kSecAttrAccessGroup',
    'labl': 'kSecAttrLabel',
    'srvr': 'kSecAttrServer',
    'cdat': 'kSecAttrCreationDate',
    'accc': 'kSecAttrAccessControl',
    'gena': 'kSecAttrGeneric',
    'sync': 'kSecAttrSynchronizable',
    'mdat': 'kSecAttrModificationDate',
    'desc': 'kSecAttrDescription',
    'icmt': 'kSecAttrComment',
    'crtr': 'kSecAttrCreator',
    'type': 'kSecAttrType',
    'scrp': 'kSecAttrScriptCode',
    'alis': 'kSecAttrAlias',
    'invi': 'kSecAttrIsInvisible',
    'nega': 'kSecAttrIsNegative',
    'cusi': 'kSecAttrHasCustomIcon',
    'prot': 'kSecProtectedDataItemAttr',
    'pdmn': 'kSecAttrAccessible',
    'ak': 'kSecAttrAccessibleWhenUnlocked',
    'ck': 'kSecAttrAccessibleAfterFirstUnlock',
    'dk': 'kSecAttrAccessibleAlways',
    'aku': 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
    'cku': 'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly',
    'dku': 'kSecAttrAccessibleAlwaysThisDeviceOnly',
}

// the base query dictionary to use for the keychain lookups
var search_dictionary = NSMutableDictionary.alloc().init();
search_dictionary.setObject_forKey_(kCFBooleanTrue, kSecReturnAttributes);
search_dictionary.setObject_forKey_(kCFBooleanTrue, kSecReturnData);
search_dictionary.setObject_forKey_(kCFBooleanTrue, kSecReturnRef);
search_dictionary.setObject_forKey_(kSecMatchLimitAll, kSecMatchLimit);

// keychain item times to query for
var item_classes = [
    kSecClassKey,
    kSecClassIdentity,
    kSecClassCertificate,
    kSecClassGenericPassword,
    kSecClassInternetPassword,
];

// get the string representation of some data
// ref: https://www.frida.re/docs/examples/ios/
function odas(raw_data) {

    // "objective-c data as string"

    // // TODO: check if this is something we need NSKeyedUnarchiver for
    // if (raw_data.toString().toLowerCase()
    //     .indexOf('62706c69 73743030 d4010203 04050609 0a582476 65727369 6f6e5824 6f626a65 63747359 24617263 68697665 72542474')) {

    //         var new_value = NSKeyedUnarchiver.unarchiveObjectWithData_(raw_data);
    //         console.log(new_value);
    //         console.log(new_value.$ownMethods);
    //     }

    // try and get a string representation of the data
    try {

        var data_instance = new ObjC.Object(raw_data);
        return Memory.readUtf8String(data_instance.bytes(), data_instance.length());

    } catch (_) {

        try {

            return raw_data.toString();

        } catch (_) {

            return '';
        }
    }
}

function decodeACL(entry){
    var SecAccessControlGetConstraints = new NativeFunction(ptr(Module.findExportByName("Security","SecAccessControlGetConstraints")),'pointer',['pointer']);
    var finalDecodedValue = "";
    if (entry.containsKey_(kSecAttrAccessControl)){
        var accessControls = ObjC.Object(SecAccessControlGetConstraints(entry.objectForKey_(kSecAttrAccessControl)));
        if (accessControls.handle != 0x00){
            var accessControlEnumerator = accessControls.keyEnumerator();
            var accessControlItemKey;
            var finalUserPresence = "";
            while ((accessControlItemKey = accessControlEnumerator.nextObject()) !== null) {
            var accessControlItem = accessControls.objectForKey_(accessControlItemKey);
            switch (odas(accessControlItemKey)) {
                case "dacl":
                    return "Default ACL";
                case "osgn":
                    finalDecodedValue += "PrivateKeyUsage "
                case "od":
                    var constraints = accessControlItem;
                    var constraintEnumerator = constraints.keyEnumerator();
                    var constraintItemKey;
                    while ((constraintItemKey = constraintEnumerator.nextObject()) !== null){
                        switch (odas(constraintItemKey)) {
                            case "cpo":
                                finalDecodedValue += " UserPresence "
                                break;
                            case "cup":
                                finalDecodedValue += " DevicePasscode "
                                break;
                            case "pkofn":
                                finalDecodedValue += (constraints.objectForKey_("pkofn") == 1 ? " Or " : " And ")
                                break;
                            case "cbio":
                                finalDecodedValue += ((constraints.objectForKey_("cbio").count()) == 1 ? " TouchIDAny " : " TouchIDCurrentSet ")
                                break;
                            default:
                                break;
                        }
                    }
                    break;
                case "prp":
                    finalDecodedValue += "ApplicationPassword"
                    break;
                default:
                    break;
                }
            }
        }
    }
    return finalDecodedValue;
}

// helper to lookup the constant name of a constant value
function get_constant_for_value(v) {

    for (var k in kSecConstantReverse) {
        if (k == v) {
            return kSecConstantReverse[v];
        }
    }

    return v;
}

// a list of keychain items that will return 
var keychain_items = [];

for (item_class_index in item_classes) {

    var item_class = item_classes[item_class_index];

    // set the class-type we are querying for now
    search_dictionary.setObject_forKey_(item_class, kSecClass);

    // get a pointer to write results to. no type? guess that goes as id* then
    var results_pointer = Memory.alloc(Process.pointerSize);

    // get the keychain items
    var copy_results = SecItemCopyMatching(search_dictionary, results_pointer);

    // if we have no results, move to the next
    if (copy_results != 0x00) {
        continue;
    }

    // read the resultant dict of the lookup from memory
    var search_results = new ObjC.Object(Memory.readPointer(results_pointer));

    // if there are search results, loop them each and populate the return
    // array with the data we got
    if (search_results.count() > 0) {

        for (var i = 0; i < search_results.count(); i++) {

            // the *actual* keychain item is here!
            search_result = search_results.objectAtIndex_(i);

            // dumped entries from NSLog() look like
            // 2017-06-20 11:25:07.645 PewPew[51023:7644106] {
            //     acct = <63726564 735f6173 5f737472 696e67>;
            //     agrp = "8AH3PS2AS7.com.sensepost.PewPew";
            //     cdat = "2017-06-20 08:06:04 +0000";
            //     class = genp;
            //     gena = <63726564 735f6173 5f737472 696e67>;
            //     mdat = "2017-06-20 08:06:04 +0000";
            //     musr = <>;
            //     pdmn = cku;
            //     svce = "";
            //     sync = 0;
            //     tomb = 0;
            //     "v_Data" = <7b227573 6e656b22 7d>;
            // }

            // Frida console.log() looks like...
            // {
            //     acct = "LOCALE_KEY";
            //     agrp = "8AH3PS2AS7.com.sensepost.blank-provision";
            //     cdat = "2017-06-23 09:51:37 +0000";
            //     class = genp;
            //     invi = 1;
            //     labl = Supercell;
            //     mdat = "2017-06-23 09:51:37 +0000";
            //     musr = <>;
            //     pdmn = ak;
            //     svce = "com.supercell";
            //     sync = 0;
            //     tomb = 0;
            //     "v_Data" = <454e>;
            // }

            // column definitions

            // cdat	kSecAttrCreationDate	Item creation date in Unix epoch time format
            // mdat	kSecAttrModificationDate	Item modification date in Unix epoch time format
            // desc	kSecAttrDescription	User visible string that describes the item
            // icmt	kSecAttrComment	User editable comment for the item
            // crtr	kSecAttrCreator	Application created (4 char) code
            // type	kSecAttrType	Item type
            // scrp	kSecAttrScriptCode	String script code (such as encoding type)
            // labl	kSecAttrLabel	Label to be displayed to the user (print name)
            // alis	kSecAttrAlias	Item alias
            // invi	kSecAttrIsInvisible	Invisible
            // nega	kSecAttrIsNegative	Invalid item
            // cusi	kSecAttrHasCustomIcon	Existence of application specific icon (Boolean)
            // prot	kSecProtectedDataItemAttr ?	Items data is protected (Boolean)
            // acct	kSecAttrAccount	Account key (such as user id)
            // svce	kSecAttrService	Service name (such as Application identifier)
            // gena	kSecAttrGeneric	User defined attribute
            // data	kSecValueData Actual data (such as password, crypto key)
            // agrp	kSecAttrAccessGroup	Keychain access group
            // pdmn	kSecAttrAccessible	Access restrictions (Data protection classes)

            // TODO: Decode accc (eg: kSecAccessControlTouchIDCurrentSet)

            var keychain_entry = {
                'item_class': get_constant_for_value(item_class),
                'create_date': odas(search_result.objectForKey_(kSecAttrCreationDate)),
                'modification_date': odas(search_result.objectForKey_(kSecAttrModificationDate)),
                'description': odas(search_result.objectForKey_(kSecAttrDescription)),
                'comment': odas(search_result.objectForKey_(kSecAttrComment)),
                'creator': odas(search_result.objectForKey_(kSecAttrCreator)),
                'type': odas(search_result.objectForKey_(kSecAttrType)),
                'script_code': odas(search_result.objectForKey_(kSecAttrScriptCode)),
                'alias': odas(search_result.objectForKey_(kSecAttrAlias)),
                'invisible': odas(search_result.objectForKey_(kSecAttrIsInvisible)),
                'negative': odas(search_result.objectForKey_(kSecAttrIsNegative)),
                'custom_icon': odas(search_result.objectForKey_(kSecAttrHasCustomIcon)),
                'protected': odas(search_result.objectForKey_(kSecProtectedDataItemAttr)),
                'access_control': decodeACL(search_result),
                'accessible_attribute': get_constant_for_value(odas(search_result.objectForKey_(kSecAttrAccessible))),
                'entitlement_group': odas(search_result.objectForKey_(kSecAttrAccessGroup)),
                'generic': odas(search_result.objectForKey_(kSecAttrGeneric)),
                'service': odas(search_result.objectForKey_(kSecAttrService)),
                'account': odas(search_result.objectForKey_(kSecAttrAccount)),
                'label': odas(search_result.objectForKey_(kSecAttrLabel)),
                'data': odas(search_result.objectForKey_('v_Data')),
            };

            keychain_items.push(keychain_entry);
        }
    }
}

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'ios-keychaindump',
    data: keychain_items
}

send(JSON.stringify(response));

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
