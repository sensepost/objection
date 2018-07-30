const nativeExports: any = {
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
    argTypes: ["pointer"],
    exportName: "SecItemDelete",
    moduleName: "Security",
    retType: "pointer",
  },
};

const api: any = {
  SecAccessControlGetConstraints: null,
  SecItemAdd: null,
  SecItemCopyMatching: null,
  SecItemDelete: null,
};

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
