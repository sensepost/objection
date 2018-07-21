const nativeExports = {
    SecAccessControlGetConstraints: {
        argTypes: ["pointer"],
        exportName: "SecAccessControlGetConstraints",
        moduleName: "Security",
        retType: "pointer",
    },
    SecItemAdd: {
        argTypes: ["pointer", "pointer"],
        exportName: "SecItemAdd",
        moduleName: "Security",
        retType: "pointer",
    },
    SecItemCopyMatching: {
        argTypes: ["pointer", "pointer"],
        exportName: "SecItemCopyMatching",
        moduleName: "Security",
        retType: "pointer",
    },
    SecItemDelete: {
        argTypes: ["pointer" ],
        exportName: "SecItemDelete",
        moduleName: "Security",
        retType: "pointer",
    },
};

const api = {
    SecAccessControlGetConstraints: null,
    SecItemAdd: null,
    SecItemCopyMatching: null,
    SecItemDelete: null,
};

export type NSDictionary = any;
export type NSMutableDictionary = any;
export type NSString = any;

export type CFDictionaryRef = any;
export type CFTypeRef = any;

// proxy method resolution
export const libObjc = new Proxy(api, {
    get: (target, key) => {

        if (target[key] === null) {
            target[key] = new NativeFunction(Module.findExportByName(
                nativeExports[key].moduleName, nativeExports[key].exportName),
                nativeExports[key].retType, nativeExports[key].argTypes);
        }

        return target[key];
    },
});
