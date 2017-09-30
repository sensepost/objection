// Deletes all of the keychain items available to the current
// application.

var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
var SecItemDelete = new NativeFunction(
    ptr(Module.findExportByName('Security', 'SecItemDelete')), 'pointer', ['pointer']);

// the base query dictionary to use for the keychain lookups
var search_dictionary = NSMutableDictionary.alloc().init();

// constants
var kSecClass = 'class',
    kSecClassKey = 'keys',
    kSecClassIdentity = 'idnt',
    kSecClassCertificate = 'cert',
    kSecClassGenericPassword = 'genp',
    kSecClassInternetPassword = 'inet';

// keychain item times to query for
var item_classes = [
    kSecClassKey,
    kSecClassIdentity,
    kSecClassCertificate,
    kSecClassGenericPassword,
    kSecClassInternetPassword
];

for (var item_class_index in item_classes) {

    var item_class = item_classes[item_class_index];

    // set the class-type we are querying for now
    search_dictionary.setObject_forKey_(item_class, kSecClass);

    // delete the classes items.
    SecItemDelete(search_dictionary);
}

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'ios-keychaindump',
    data: 'Keychain cleared'
};

send(response);

// -- Sample Objective-C
//
// NSMutableDictionary *query = [[NSMutableDictionary alloc] init];

// for (id itemClass in itemClasses) {

//     NSLog(@"Querying: %@", itemClass);
//     [query setObject:itemClass forKey:(__bridge id)kSecClass];

//     OSStatus findStatus = SecItemDelete((__bridge CFDictionaryRef)query);

// }
