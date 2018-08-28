// Retrieves some information about the iOS device.

var UIDevice = ObjC.classes.UIDevice;
var NSBundle = ObjC.classes.NSBundle;

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'device-info',
    data: {
        applicationName: NSBundle.mainBundle().objectForInfoDictionaryKey_('CFBundleIdentifier').toString(),
        deviceName: UIDevice.currentDevice().name().toString(),
        systemName: UIDevice.currentDevice().systemName().toString(),
        model: UIDevice.currentDevice().model().toString(),
        systemVersion: UIDevice.currentDevice().systemVersion().toString(),
        identifierForVendor: UIDevice.currentDevice().identifierForVendor().toString()
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
