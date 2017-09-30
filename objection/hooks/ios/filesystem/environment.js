// Gets some 'environmental' information about the current application,
// primarily by getting the locations of interesting app related directories.

var NSFileManager = ObjC.classes.NSFileManager;
var NSBundle = ObjC.classes.NSBundle;

var fm = NSFileManager.defaultManager();
var mb = NSBundle.mainBundle();

// typedef NS_ENUM(NSUInteger, NSSearchPathDirectory) {
//     NSApplicationDirectory = 1,             // supported applications (Applications)
//     NSDemoApplicationDirectory,             // unsupported applications, demonstration versions (Demos)
//     NSDeveloperApplicationDirectory,        // developer applications (Developer/Applications). DEPRECATED - there is no one single Developer directory.
//     NSAdminApplicationDirectory,            // system and network administration applications (Administration)
//     NSLibraryDirectory,                     // various documentation, support, and configuration files, resources (Library)
//     NSDeveloperDirectory,                   // developer resources (Developer) DEPRECATED - there is no one single Developer directory.
//     NSUserDirectory,                        // user home directories (Users)
//     NSDocumentationDirectory,               // documentation (Documentation)
//     NSDocumentDirectory,                    // documents (Documents)
//     NSCoreServiceDirectory,                 // location of CoreServices directory (System/Library/CoreServices)
//     NSAutosavedInformationDirectory NS_ENUM_AVAILABLE(10_6, 4_0) = 11,   // location of autosaved documents (Documents/Autosaved)
//     NSDesktopDirectory = 12,                // location of user's desktop
//     NSCachesDirectory = 13,                 // location of discardable cache files (Library/Caches)
//     NSApplicationSupportDirectory = 14,     // location of application support files (plug-ins, etc) (Library/Application Support)
//
//     [... snip ...]
//
// };

var NSApplicationDirectory = 1,
    NSDemoApplicationDirectory = 2,
    NSDeveloperApplicationDirectory = 3,
    NSAdminApplicationDirectory = 4,
    NSLibraryDirectory = 5,
    NSDeveloperDirectory = 6,
    NSUserDirectory = 7,
    NSDocumentationDirectory = 8,
    NSDocumentDirectory = 9,
    NSCoreServiceDirectory = 10,
    NSAutosavedInformationDirectory = 11,
    NSDesktopDirectory = 12,
    NSCachesDirectory = 13,
    NSApplicationSupportDirectory = 14,

    // lastly, NSUserDomainMask from NS_OPTIONS == 1
    NSUserDomainMask = 1;

// Returns a string of the path from a ENUM.
function getPathForNSLocation(NSSomeLocationDirectory) {

    var p = fm.URLsForDirectory_inDomains_(NSSomeLocationDirectory, NSUserDomainMask)
        .lastObject();

    // check that the lookup had data
    if (p) {
        return p.path().toString();
    } else {

        return '';
    }
}

var data = {

    // most interesting directories
    DocumentDirectory: getPathForNSLocation(NSDocumentDirectory),
    LibraryDirectory: getPathForNSLocation(NSLibraryDirectory),
    CachesDirectory: getPathForNSLocation(NSCachesDirectory),
    BundlePath: mb.bundlePath().toString(),

    // other directories
    ApplicationDirectory: getPathForNSLocation(NSApplicationDirectory),
    DemoApplicationDirectory: getPathForNSLocation(NSDemoApplicationDirectory),
    DeveloperApplicationDirectory: getPathForNSLocation(NSDeveloperApplicationDirectory),
    UserDirectory: getPathForNSLocation(NSUserDirectory),
    CoreServiceDirectory: getPathForNSLocation(NSCoreServiceDirectory),
    AutosavedInformationDirectory: getPathForNSLocation(NSAutosavedInformationDirectory),
    DesktopDirectory: getPathForNSLocation(NSDesktopDirectory),
    ApplicationSupportDirectory: getPathForNSLocation(NSApplicationSupportDirectory),

    // data from the NSBundle
    ReceiptPath: mb.appStoreReceiptURL().path().toString(),
    ResourcePath: mb.resourcePath().toString()
};

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'environment-directories',
    data: data 
};

send(response);

// -- Sample Objective-C
//
// NSFileManager *fm = [NSFileManager defaultManager];
// NSString *pictures = [[fm URLsForDirectory:NSPicturesDirectory inDomains:NSUserDomainMask] lastObject].path;
// NSBundle *bundle = [NSBundle mainBundle];
// NSString *bundlePath = [bundle bundlePath];
// NSString *receipt = [bundle appStoreReceiptURL].path;
// NSString *resourcePath = [bundle resourcePath];
