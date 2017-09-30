// Retrieves some information about the iOS device.

var UIDevice = ObjC.classes.UIDevice;
var NSBundle = ObjC.classes.NSBundle;

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'device-info',
    data: {
        applicationName: String(NSBundle.mainBundle().objectForInfoDictionaryKey_('CFBundleIdentifier')),
        deviceName: String(UIDevice.currentDevice().name()),
        systemName: String(UIDevice.currentDevice().systemName()),
        model: String(UIDevice.currentDevice().model()),
        systemVersion: String(UIDevice.currentDevice().systemVersion()),
        identifierForVendor: String(UIDevice.currentDevice().identifierForVendor())
    }
};

send(response);

// -- Sample Objective-C
//
// NSDictionary *deviceIdentifiers = @{
//                             @"name": [[UIDevice currentDevice] name],
//                             @"systemName": [[UIDevice currentDevice] systemName],
//                             @"systemVersion": [[UIDevice currentDevice] systemVersion],
//                             };
