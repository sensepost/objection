(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
});

var e = require("./ios/keychain"), n = require("./version"), r = new e.IosKeychain();

rpc.exports = {
  keychainAdd: function(e, n) {
    return r.add(e, n);
  },
  keychainEmpty: function() {
    return r.empty();
  },
  keychainList: function() {
    return r.list();
  },
  version: function() {
    return n.version;
  }
};

},{"./ios/keychain":2,"./version":6}],2:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
});

var e = require("../lib/ios/constants"), t = require("../lib/ios/helpers"), c = require("../lib/ios/libobjc"), r = ObjC.classes, o = r.NSMutableDictionary, a = r.NSString, s = 4, i = [ e.kSec.kSecClassKey, e.kSec.kSecClassIdentity, e.kSec.kSecClassCertificate, e.kSec.kSecClassGenericPassword, e.kSec.kSecClassInternetPassword ], n = function() {
  function r() {}
  return r.prototype.empty = function() {
    var t = o.alloc().init();
    i.forEach(function(r) {
      t.setObject_forKey_(r, e.kSec.kSecClass), c.libObjc.SecItemDelete(t);
    });
  }, r.prototype.list = function() {
    var r = this, a = ObjC.classes.__NSCFBoolean.numberWithBool_(!0), s = o.alloc().init();
    return s.setObject_forKey_(a, e.kSec.kSecReturnAttributes), s.setObject_forKey_(a, e.kSec.kSecReturnData), 
    s.setObject_forKey_(a, e.kSec.kSecReturnRef), s.setObject_forKey_(e.kSec.kSecMatchLimitAll, e.kSec.kSecMatchLimit), 
    [].concat.apply([], i.map(function(o) {
      var a = [];
      s.setObject_forKey_(o, e.kSec.kSecClass);
      var i = Memory.alloc(Process.pointerSize);
      if (c.libObjc.SecItemCopyMatching(s, i).isNull()) {
        var n = new ObjC.Object(Memory.readPointer(i));
        if (!(n.length <= 0)) {
          for (var _ = 0; _ < n.count(); _++) {
            var S = n.objectAtIndex_(_);
            a.push({
              access_control: S.containsKey_(e.kSec.kSecAttrAccessControl) ? r.decode_acl(S) : "",
              accessible_attribute: e.kSec[S.objectForKey_(e.kSec.kSecAttrAccessible)],
              account: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrAccount)),
              alias: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrAlias)),
              comment: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrComment)),
              create_date: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrCreationDate)),
              creator: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrCreator)),
              custom_icon: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrHasCustomIcon)),
              data: t.data_to_string(S.objectForKey_(e.kSec.kSecValueData)),
              description: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrDescription)),
              entitlement_group: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrAccessGroup)),
              generic: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrGeneric)),
              invisible: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrIsInvisible)),
              item_class: o,
              label: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrLabel)),
              modification_date: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrModificationDate)),
              negative: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrIsNegative)),
              protected: t.data_to_string(S.objectForKey_(e.kSec.kSecProtectedDataItemAttr)),
              script_code: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrScriptCode)),
              service: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrService)),
              type: t.data_to_string(S.objectForKey_(e.kSec.kSecAttrType))
            });
          }
          return a;
        }
      }
    }).filter(function(e) {
      return void 0 !== e;
    }));
  }, r.prototype.add = function(t, r) {
    var i = a.stringWithString_(r).dataUsingEncoding_(s), n = a.stringWithString_(t).dataUsingEncoding_(s), _ = o.alloc().init();
    return _.setObject_forKey_(e.kSec.kSecClassGenericPassword, e.kSec.kSecClass), _.setObject_forKey_(n, e.kSec.kSecAttrService), 
    _.setObject_forKey_(i, e.kSec.kSecValueData), 0 === c.libObjc.SecItemAdd(_, NULL);
  }, r.prototype.decode_acl = function(r) {
    var o = new ObjC.Object(c.libObjc.SecAccessControlGetConstraints(r.objectForKey_(e.kSec.kSecAttrAccessControl)));
    if (o.handle.isNull()) return "";
    for (var a, s = [], i = o.keyEnumerator(); null !== (a = i.nextObject()); ) {
      var n = o.objectForKey_(a);
      switch (t.data_to_string(a)) {
       case "dacl":
        break;

       case "osgn":
        s.push("kSecAttrKeyClassPrivate");

       case "od":
        for (var _ = n, S = _.keyEnumerator(), k = void 0; null !== (k = S.nextObject()); ) switch (t.data_to_string(k)) {
         case "cpo":
          s.push("kSecAccessControlUserPresence");
          break;

         case "cup":
          s.push("kSecAccessControlDevicePasscode");
          break;

         case "pkofn":
          1 === _.objectForKey_("pkofn") ? s.push("Or") : s.push("And");
          break;

         case "cbio":
          1 === _.objectForKey_("cbio").count() ? s.push("kSecAccessControlBiometryAny") : s.push("kSecAccessControlBiometryCurrentSet");
        }
        break;

       case "prp":
        s.push("kSecAccessControlApplicationPassword");
      }
    }
    return "";
  }, r;
}();

exports.IosKeychain = n;

},{"../lib/ios/constants":3,"../lib/ios/helpers":4,"../lib/ios/libobjc":5}],3:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
});

var e;

!function(e) {
  e.kSecReturnAttributes = "r_Attributes", e.kSecReturnData = "r_Data", e.kSecReturnRef = "r_Ref", 
  e.kSecMatchLimit = "m_Limit", e.kSecMatchLimitAll = "m_LimitAll", e.kSecClass = "class", 
  e.kSecClassKey = "keys", e.kSecClassIdentity = "idnt", e.kSecClassCertificate = "cert", 
  e.kSecClassGenericPassword = "genp", e.kSecClassInternetPassword = "inet", e.kSecAttrService = "svce", 
  e.kSecAttrAccount = "acct", e.kSecAttrAccessGroup = "agrp", e.kSecAttrLabel = "labl", 
  e.kSecAttrCreationDate = "cdat", e.kSecAttrAccessControl = "accc", e.kSecAttrGeneric = "gena", 
  e.kSecAttrSynchronizable = "sync", e.kSecAttrModificationDate = "mdat", e.kSecAttrServer = "srvr", 
  e.kSecAttrDescription = "desc", e.kSecAttrComment = "icmt", e.kSecAttrCreator = "crtr", 
  e.kSecAttrType = "type", e.kSecAttrScriptCode = "scrp", e.kSecAttrAlias = "alis", 
  e.kSecAttrIsInvisible = "invi", e.kSecAttrIsNegative = "nega", e.kSecAttrHasCustomIcon = "cusi", 
  e.kSecProtectedDataItemAttr = "prot", e.kSecAttrAccessible = "pdmn", e.kSecAttrAccessibleWhenUnlocked = "ak", 
  e.kSecAttrAccessibleAfterFirstUnlock = "ck", e.kSecAttrAccessibleAlways = "dk", 
  e.kSecAttrAccessibleWhenUnlockedThisDeviceOnly = "aku", e.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly = "akpu", 
  e.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = "cku", e.kSecAttrAccessibleAlwaysThisDeviceOnly = "dku", 
  e.kSecValueData = "v_Data";
}(e = exports.kSec || (exports.kSec = {}));

},{}],4:[function(require,module,exports){
"use strict";

function t(t) {
  try {
    var e = new ObjC.Object(t);
    return Memory.readUtf8String(e.bytes(), e.length());
  } catch (e) {
    try {
      return t.toString();
    } catch (t) {
      return "";
    }
  }
}

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.data_to_string = t;

},{}],5:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
});

var e = {
  SecAccessControlGetConstraints: {
    argTypes: [ "pointer" ],
    exportName: "SecAccessControlGetConstraints",
    moduleName: "Security",
    retType: "pointer"
  },
  SecItemAdd: {
    argTypes: [ "pointer", "pointer" ],
    exportName: "SecItemAdd",
    moduleName: "Security",
    retType: "pointer"
  },
  SecItemCopyMatching: {
    argTypes: [ "pointer", "pointer" ],
    exportName: "SecItemCopyMatching",
    moduleName: "Security",
    retType: "pointer"
  },
  SecItemDelete: {
    argTypes: [ "pointer" ],
    exportName: "SecItemDelete",
    moduleName: "Security",
    retType: "pointer"
  }
}, t = {
  SecAccessControlGetConstraints: null,
  SecItemAdd: null,
  SecItemCopyMatching: null,
  SecItemDelete: null
};

exports.libObjc = new Proxy(t, {
  get: function(t, r) {
    return null === t[r] && (t[r] = new NativeFunction(Module.findExportByName(e[r].moduleName, e[r].exportName), e[r].retType, e[r].argTypes)), 
    t[r];
  }
});

},{}],6:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.version = "1.0.0";

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJzcmMvaW5kZXgudHMiLCJzcmMvaW9zL2tleWNoYWluLnRzIiwic3JjL2xpYi9pb3MvY29uc3RhbnRzLnRzIiwic3JjL2xpYi9pb3MvaGVscGVycy50cyIsInNyYy9saWIvaW9zL2xpYm9iamMudHMiLCJzcmMvdmVyc2lvbi50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7OztBQ0FBLElBQUEsSUFBQSxRQUFBLG1CQUNBLElBQUEsUUFBQSxjQUVNLElBQXdCLElBQUksRUFBQTs7QUFFbEMsSUFBSTtFQUdBLGFBQWEsU0FBQyxHQUFhO0lBQWlCLE9BQUEsRUFBUyxJQUFJLEdBQUs7O0VBQzlELGVBQWU7SUFBTSxPQUFBLEVBQVM7O0VBQzlCLGNBQWM7SUFBTSxPQUFBLEVBQVM7O0VBRzdCLFNBQVM7SUFBTSxPQUFBLEVBQUE7Ozs7Ozs7Ozs7O0FDWG5CLElBQUEsSUFBQSxRQUFBLHlCQUNBLElBQUEsUUFBQSx1QkFFQSxJQUFBLFFBQUEsdUJBT00sSUFBQSxLQUFBLFNBQUUsSUFBQSxFQUFBLHFCQUFxQixJQUFBLEVBQUEsVUFDdkIsSUFBdUIsR0FHdkIsTUFDRixFQUFBLEtBQUssY0FDTCxFQUFBLEtBQUssbUJBQ0wsRUFBQSxLQUFLLHNCQUNMLEVBQUEsS0FBSywwQkFDTCxFQUFBLEtBQUssNkJBSVQsSUFBQTtFQUFBLFNBQUE7RUF5TEEsT0F0TFcsRUFBQSxVQUFBLFFBQVA7SUFFSSxJQUFNLElBQW1CLEVBQW9CLFFBQVE7SUFFckQsRUFBWSxRQUFRLFNBQUM7TUFHakIsRUFBaUIsa0JBQWtCLEdBQU8sRUFBQSxLQUFLLFlBQy9DLEVBQUEsUUFBUSxjQUFjOztLQU12QixFQUFBLFVBQUEsT0FBUDtJQUFBLElBQUEsSUFBQSxNQUVVLElBQWlCLEtBQUssUUFBUSxjQUFjLGlCQUFnQixJQUc1RCxJQUFtQixFQUFvQixRQUFRO0lBOERyRCxPQTdEQSxFQUFpQixrQkFB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
