// NSDictionary *deviceIdentifiers = @{
//                             @"name": [[UIDevice currentDevice] name],
//                             @"systemName": [[UIDevice currentDevice] systemName],
//                             @"systemVersion": [[UIDevice currentDevice] systemVersion],
//                             };

// [NSString stringWithString:@"Hello World"]
// var NSString = ObjC.classes.NSString; NSString.stringWithString_("Hello World");
var UIDevice = ObjC.classes.UIDevice;

var response = {
    status: "success",
    error_reason: NaN,
    type: "device-info",
    data: {
        deviceName: String(UIDevice.currentDevice().name()),
        systemName: String(UIDevice.currentDevice().systemName()),
        model: String(UIDevice.currentDevice().model()),
        systemVersion: String(UIDevice.currentDevice().systemVersion()),
        identifierForVendor: String(UIDevice.currentDevice().identifierForVendor()),
    }
}

send(JSON.stringify(response));
