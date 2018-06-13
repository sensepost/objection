// Adds a new keychain entry.

var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
var NSString = ObjC.classes.NSString;

var SecItemAdd = new NativeFunction(
    ptr(Module.findExportByName('Security', 'SecItemAdd')), 'pointer', ['pointer', 'pointer']);

// constants
var NSUTF8StringEncoding = 4;
var kSecClass = 'class',
    kSecClassKey = 'keys',
    kSecClassIdentity = 'idnt',
    kSecClassCertificate = 'cert',
    kSecClassGenericPassword = 'genp',
    kSecClassInternetPassword = 'inet',
    kSecAttrService = 'svce',
    kSecValueData = 'v_Data';

rpc.exports = {
    add: function (key, data) {

        // Convert the key and data to NSData
        data_value = NSString.stringWithString_(data).dataUsingEncoding_(NSUTF8StringEncoding);
        data_key = NSString.stringWithString_(key).dataUsingEncoding_(NSUTF8StringEncoding);

        // console.log(new ObjC.Object(data_key).$className);

        var item_dictionary = NSMutableDictionary.alloc().init();

        item_dictionary.setObject_forKey_(kSecClassGenericPassword, kSecClass);
        item_dictionary.setObject_forKey_(data_key, kSecAttrService);
        item_dictionary.setObject_forKey_(data_value, kSecValueData);

        var results_pointer = Memory.alloc(Process.pointerSize);

        // Add the keychain entry
        var result = SecItemAdd(item_dictionary, results_pointer);

        if (result != 0x00) {

            return false;

        } else {

            return true;
        }
    }
}

// NSMutableDictionary *dict = [[NSMutableDictionary alloc] init];
// [dict setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];

// NSData *encodedKey = [key dataUsingEncoding:NSUTF8StringEncoding];
// [dict setObject:encodedKey forKey:(__bridge id)kSecAttrGeneric];
// [dict setObject:encodedKey forKey:(__bridge id)kSecAttrService];
// [dict setObject:encodedKey forKey:(__bridge id)kSecAttrAccount];
// [dict setObject:data forKey:(__bridge id)kSecValueData];

// OSStatus status = SecItemAdd((__bridge CFDictionaryRef)dict, NULL);
// if(errSecSuccess != status) {

//     NSLog(@"Unable add item with key =%@ error:%d", key, (int)status);
// }

// return (errSecSuccess == status);
