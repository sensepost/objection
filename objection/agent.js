(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
});

var e = require("./ios/keychain"), n = new e.IosKeychain();

rpc.exports = {
  keychainAdd: function() {
    return n.add.bind(n);
  },
  keychainDump: function() {
    return n.list.bind(n);
  },
  keychainEmpty: function() {
    return n.empty.bind(n);
  }
};

},{"./ios/keychain":2}],2:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
});

var e = require("../lib/ios/constants"), t = require("../lib/ios/helpers"), c = require("../lib/ios/libios"), r = ObjC.classes, o = r.NSMutableDictionary, a = r.NSString, s = 4, i = [ e.kSec.kSecClassKey, e.kSec.kSecClassIdentity, e.kSec.kSecClassCertificate, e.kSec.kSecClassGenericPassword, e.kSec.kSecClassInternetPassword ], n = function() {
  function r() {}
  return r.prototype.empty = function() {
    var t = o.alloc().init();
    i.forEach(function(r) {
      t.setObject_forKey_(r, e.kSec.kSecClass), c.SecItemDelete(t);
    });
  }, r.prototype.list = function() {
    var r = this, a = o.alloc().init();
    return a.setObject_forKey_(c.kCFBooleanTrue, e.kSec.kSecReturnAttributes), a.setObject_forKey_(c.kCFBooleanTrue, e.kSec.kSecReturnData), 
    a.setObject_forKey_(c.kCFBooleanTrue, e.kSec.kSecReturnRef), a.setObject_forKey_(e.kSec.kSecMatchLimitAll, e.kSec.kSecMatchLimit), 
    [].concat.apply([], i.map(function(o) {
      var s = [];
      a.setObject_forKey_(o, e.kSec.kSecClass);
      var i = Memory.alloc(Process.pointerSize);
      if (c.SecItemCopyMatching(a, i).isNull()) {
        var n = new ObjC.Object(Memory.readPointer(i));
        if (!(n.length <= 0)) {
          for (var _ = 0; _ < n.count(); _++) {
            var S = n.objectAtIndex_(_);
            s.push({
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
          return s;
        }
      }
    }).filter(function(e) {
      return void 0 !== e;
    }));
  }, r.prototype.add = function(t, r) {
    var i = a.stringWithString_(r).dataUsingEncoding_(s), n = a.stringWithString_(t).dataUsingEncoding_(s), _ = o.alloc().init();
    return _.setObject_forKey_(e.kSec.kSecClassGenericPassword, e.kSec.kSecClass), _.setObject_forKey_(n, e.kSec.kSecAttrService), 
    _.setObject_forKey_(i, e.kSec.kSecValueData), 0 === c.SecItemAdd(_, NULL);
  }, r.prototype.decode_acl = function(r) {
    var o = new ObjC.Object(c.SecAccessControlGetConstraints(r.objectForKey_(e.kSec.kSecAttrAccessControl)));
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

},{"../lib/ios/constants":3,"../lib/ios/helpers":4,"../lib/ios/libios":5}],3:[function(require,module,exports){
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
}), exports.SecItemCopyMatching = new NativeFunction(Module.findExportByName("Security", "SecItemCopyMatching"), "pointer", [ "pointer", "pointer" ]), 
exports.SecAccessControlGetConstraints = new NativeFunction(Module.findExportByName("Security", "SecAccessControlGetConstraints"), "pointer", [ "pointer" ]), 
exports.SecItemDelete = new NativeFunction(Module.findExportByName("Security", "SecItemDelete"), "pointer", [ "pointer" ]), 
exports.SecItemAdd = new NativeFunction(Module.findExportByName("Security", "SecItemAdd"), "pointer", [ "pointer", "pointer" ]), 
exports.kCFBooleanTrue = ObjC.classes.__NSCFBoolean.numberWithBool_(!0);

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJzcmMvaW5kZXgudHMiLCJzcmMvaW9zL2tleWNoYWluLnRzIiwic3JjL2xpYi9pb3MvY29uc3RhbnRzLnRzIiwic3JjL2xpYi9pb3MvaGVscGVycy50cyIsInNyYy9saWIvaW9zL2xpYmlvcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7OztBQ0FBLElBQUEsSUFBQSxRQUFBLG1CQUVNLElBQVcsSUFBSSxFQUFBOztBQUVyQixJQUFJO0VBQ0EsYUFBYTtJQUFNLE9BQUEsRUFBUyxJQUFJLEtBQUs7O0VBQ3JDLGNBQWM7SUFBTSxPQUFBLEVBQVMsS0FBSyxLQUFLOztFQUN2QyxlQUFlO0lBQU0sT0FBQSxFQUFTLE1BQU0sS0FBSzs7Ozs7Ozs7Ozs7QUNMN0MsSUFBQSxJQUFBLFFBQUEseUJBQ0EsSUFBQSxRQUFBLHVCQUVBLElBQUEsUUFBQSxzQkFXTSxJQUFBLEtBQUEsU0FBRSxJQUFBLEVBQUEscUJBQXFCLElBQUEsRUFBQSxVQUN2QixJQUF1QixHQUd2QixNQUNGLEVBQUEsS0FBSyxjQUNMLEVBQUEsS0FBSyxtQkFDTCxFQUFBLEtBQUssc0JBQ0wsRUFBQSxLQUFLLDBCQUNMLEVBQUEsS0FBSyw2QkFJVCxJQUFBO0VBQUEsU0FBQTtFQXVMQSxPQXBMVyxFQUFBLFVBQUEsUUFBUDtJQUdJLElBQU0sSUFBbUIsRUFBb0IsUUFBUTtJQUVyRCxFQUFZLFFBQVEsU0FBQztNQUdqQixFQUFpQixrQkFBa0IsR0FBTyxFQUFBLEtBQUssWUFDL0MsRUFBQSxjQUFjOztLQU1mLEVBQUEsVUFBQSxPQUFQO0lBQUEsSUFBQSxJQUFBLE1BR1UsSUFBbUIsRUFBb0IsUUFBUTtJQTZEckQsT0E1REEsRUFBaUIsa0JBQWtCLEVBQUEsZ0JBQWdCLEVBQUEsS0FBSyx1QkFDeEQsRUFBaUIsa0JBQWtCLEVBQUEsZ0JBQWdCLEVBQUEsS0FBSztJQUN4RCxFQUFpQixrQkFBa0IsRUFBQSxn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
