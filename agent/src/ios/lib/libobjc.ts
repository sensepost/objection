const nativeExports: any = {
  // iOS keychain methods
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

  // SSL pinning methods
  SSLCreateContext: {
    argTypes: ["pointer", "int", "int"],
    exportName: "SSLCreateContext",
    moduleName: "Security",
    retType: "pointer",
  },
  SSLHandshake: {
    argTypes: ["pointer"],
    exportName: "SSLHandshake",
    moduleName: "Security",
    retType: "int",
  },
  SSLSetSessionOption: {
    argTypes: ["pointer", "int", "bool"],
    exportName: "SSLSetSessionOption",
    moduleName: "Security",
    retType: "int",
  },

  // iOS 10+ TLS methods
  nw_tls_create_peer_trust: {
    argTypes: ["pointer", "bool", "pointer"],
    exportName: "nw_tls_create_peer_trust",
    moduleName: "libnetwork.dylib",
    retType: "int",
  },
  tls_helper_create_peer_trust: {
    argTypes: ["pointer", "bool", "pointer"],
    exportName: "tls_helper_create_peer_trust",
    moduleName: "libcoretls_cfhelpers.dylib",
    retType: "int",
  },
};

const api: any = {
  SecAccessControlGetConstraints: null,
  SecItemAdd: null,
  SecItemCopyMatching: null,
  SecItemDelete: null,

  SSLCreateContext: null,
  SSLHandshake: null,
  SSLSetSessionOption: null,

  nw_tls_create_peer_trust: null,
  tls_helper_create_peer_trust: null,
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
