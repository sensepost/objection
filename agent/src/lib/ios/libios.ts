export type NSDictionary = any;
export type NSMutableDictionary = any;
export type NSString = any;

export const SecItemCopyMatching: any = new NativeFunction(
    Module.findExportByName("Security", "SecItemCopyMatching"),
    "pointer", ["pointer", "pointer"]);

export const SecAccessControlGetConstraints: any = new NativeFunction(
    Module.findExportByName("Security", "SecAccessControlGetConstraints"),
    "pointer", ["pointer"]);

export const SecItemDelete: any = new NativeFunction(
    Module.findExportByName("Security", "SecItemDelete"),
    "pointer", ["pointer"]);

export const SecItemAdd: any = new NativeFunction(
    Module.findExportByName("Security", "SecItemAdd"),
    "pointer", ["pointer", "pointer"]);

// ref: http://nshipster.com/bool/
export const kCFBooleanTrue: boolean = ObjC.classes.__NSCFBoolean.numberWithBool_(true);
