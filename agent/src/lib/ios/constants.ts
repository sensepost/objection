// constants used for Security Attributes etc.
// NSLog(@"kSecAttrService: %@", kSecAttrService);
export enum kSec {

  kSecReturnAttributes = "r_Attributes",
  kSecReturnData = "r_Data",
  kSecReturnRef = "r_Ref",
  kSecMatchLimit = "m_Limit",
  kSecMatchLimitAll = "m_LimitAll",
  kSecClass = "class",
  kSecClassKey = "keys",
  kSecClassIdentity = "idnt",
  kSecClassCertificate = "cert",
  kSecClassGenericPassword = "genp",
  kSecClassInternetPassword = "inet",
  kSecAttrService = "svce",
  kSecAttrAccount = "acct",
  kSecAttrAccessGroup = "agrp",
  kSecAttrLabel = "labl",
  kSecAttrCreationDate = "cdat",
  kSecAttrAccessControl = "accc",
  kSecAttrGeneric = "gena",
  kSecAttrSynchronizable = "sync",
  kSecAttrModificationDate = "mdat",
  kSecAttrServer = "srvr",
  kSecAttrDescription = "desc",
  kSecAttrComment = "icmt",
  kSecAttrCreator = "crtr",
  kSecAttrType = "type",
  kSecAttrScriptCode = "scrp",
  kSecAttrAlias = "alis",
  kSecAttrIsInvisible = "invi",
  kSecAttrIsNegative = "nega",
  kSecAttrHasCustomIcon = "cusi",
  kSecProtectedDataItemAttr = "prot",
  kSecAttrAccessible = "pdmn",
  kSecAttrAccessibleWhenUnlocked = "ak",
  kSecAttrAccessibleAfterFirstUnlock = "ck",
  kSecAttrAccessibleAlways = "dk",
  kSecAttrAccessibleWhenUnlockedThisDeviceOnly = "aku",
  kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly = "akpu",
  kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = "cku",
  kSecAttrAccessibleAlwaysThisDeviceOnly = "dku",
  kSecValueData = "v_Data",
}

// typedef NS_ENUM(NSUInteger, NSSearchPathDirectory) {
//     NSApplicationDirectory = 1,             // supported applications (Applications)
//     NSDemoApplicationDirectory,             // unsupported applications, demonstration versions (Demos)
// tslint:disable-next-line:max-line-length
//     NSDeveloperApplicationDirectory,        // developer applications (Developer/Applications). DEPRECATED - there is no one single Developer directory.
//     NSAdminApplicationDirectory,            // system and network administration applications (Administration)
// tslint:disable-next-line:max-line-length
//     NSLibraryDirectory,                     // various documentation, support, and configuration files, resources (Library)
// tslint:disable-next-line:max-line-length
//     NSDeveloperDirectory,                   // developer resources (Developer) DEPRECATED - there is no one single Developer directory.
//     NSUserDirectory,                        // user home directories (Users)
//     NSDocumentationDirectory,               // documentation (Documentation)
//     NSDocumentDirectory,                    // documents (Documents)
//     NSCoreServiceDirectory,                 // location of CoreServices directory (System/Library/CoreServices)
// tslint:disable-next-line:max-line-length
//     NSAutosavedInformationDirectory NS_ENUM_AVAILABLE(10_6, 4_0) = 11,   // location of autosaved documents (Documents/Autosaved)
//     NSDesktopDirectory = 12,                // location of user's desktop
//     NSCachesDirectory = 13,                 // location of discardable cache files (Library/Caches)
// tslint:disable-next-line:max-line-length
//     NSApplicationSupportDirectory = 14,     // location of application support files (plug-ins, etc) (Library/Application Support)
//
//     [... snip ...]
//
// };

export enum NSSearchPaths {
  NSApplicationDirectory = 1,
  NSDemoApplicationDirectory,
  NSDeveloperApplicationDirectory,
  NSAdminApplicationDirectory,
  NSLibraryDirectory,
  NSDeveloperDirectory,
  NSUserDirectory,
  NSDocumentationDirectory,
  NSDocumentDirectory,
  NSCoreServiceDirectory,
  NSAutosavedInformationDirectory,
  NSDesktopDirectory,
  NSCachesDirectory,
  NSApplicationSupportDirectory,
}

export const NSUserDomainMask = 1;
