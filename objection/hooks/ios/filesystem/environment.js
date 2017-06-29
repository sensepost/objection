// NSFileManager *fm = [NSFileManager defaultManager];
// NSString *pictures = [[fm URLsForDirectory:NSPicturesDirectory inDomains:NSUserDomainMask] lastObject].path;

// NSBundle *bundle = [NSBundle mainBundle];
// NSString *bundlePath = [bundle bundlePath];
// NSString *receipt = [bundle appStoreReceiptURL].path;
// NSString *resourcePath = [bundle resourcePath];

var NSFileManager = ObjC.classes.NSFileManager;
var NSBundle = ObjC.classes.NSBundle;

var fm = NSFileManager.defaultManager();
var mb = NSBundle.mainBundle();

// nice. so it doesnt seem like i can just go a-la NSPicturesDirectory & NSUserDomainMask
// and expect things to work. nope. have to map those thingies to integers from the NS_ENUM
// in Foundation/NSPathUtilities.h 

// The ENUM exceprt from the header is...

// NSApplicationDirectory = 1,             // supported applications (Applications)
// NSDemoApplicationDirectory,             // unsupported applications, demonstration versions (Demos)
// NSDeveloperApplicationDirectory,        // developer applications (Developer/Applications). DEPRECATED - there is no one single Developer directory.
// NSAdminApplicationDirectory,            // system and network administration applications (Administration)
// NSLibraryDirectory,                     // various documentation, support, and configuration files, resources (Library)
// NSDeveloperDirectory,                   // developer resources (Developer) DEPRECATED - there is no one single Developer directory.
// NSUserDirectory,                        // user home directories (Users)
// NSDocumentationDirectory,               // documentation (Documentation)
// NSDocumentDirectory,                    // documents (Documents)
// NSCoreServiceDirectory,                 // location of CoreServices directory (System/Library/CoreServices)
// NSAutosavedInformationDirectory NS_ENUM_AVAILABLE(10_6, 4_0) = 11,   // location of autosaved documents (Documents/Autosaved)
// NSDesktopDirectory = 12,                // location of user's desktop
// NSCachesDirectory = 13,                 // location of discardable cache files (Library/Caches)

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
        .lastObject()

    // check that the lookup had data
    if (p) {
        return p.path().toString();
    } else {

        return '';
    }
}

var data = {

    // data from the NSFileManager

    // most interesting directories:
    DocumentDirectory: getPathForNSLocation(NSDocumentDirectory),
    LibraryDirectory: getPathForNSLocation(NSLibraryDirectory),
    CachesDirectory: getPathForNSLocation(NSCachesDirectory),
    BundlePath: mb.bundlePath().toString(),

    // other directories
    ApplicationDirectory: getPathForNSLocation(NSApplicationDirectory),
    DemoApplicationDirectory: getPathForNSLocation(NSDemoApplicationDirectory),
    DeveloperApplicationDirectory: getPathForNSLocation(NSDeveloperApplicationDirectory),
    AdminApplicationDirectory: getPathForNSLocation(NSAdminApplicationDirectory),
    DeveloperDirectory: getPathForNSLocation(NSDeveloperDirectory),
    UserDirectory: getPathForNSLocation(NSUserDirectory),
    DocumentationDirectory: getPathForNSLocation(NSDocumentationDirectory),
    CoreServiceDirectory: getPathForNSLocation(NSCoreServiceDirectory),
    AutosavedInformationDirectory: getPathForNSLocation(NSAutosavedInformationDirectory),
    DesktopDirectory: getPathForNSLocation(NSDesktopDirectory),
    ApplicationSupportDirectory: getPathForNSLocation(NSApplicationSupportDirectory),

    // data from the NSBundle
    ReceiptPath: mb.appStoreReceiptURL().path().toString(),
    ResourcePath: mb.resourcePath().toString(),
}

var response = {
    status: "success",
    error_reason: NaN,
    type: "environment-directories",
    data: data 
}

send(JSON.stringify(response));
