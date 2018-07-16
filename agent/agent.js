(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
});

var e = require("./ios/keychain");

rpc.exports = {
  keychainDump: function() {
    return new e.IosKeychain().list();
  },
  keychainEmpty: function() {
    return new e.IosKeychain().empty();
  }
};

},{"./ios/keychain":2}],2:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
});

var e = require("../lib/ios/helpers"), t = require("../lib/ios/constants"), c = require("../lib/ios/libios"), o = ObjC.classes, r = o.NSMutableDictionary, a = o.NSString, s = [ t.kSec.kSecClassKey, t.kSec.kSecClassIdentity, t.kSec.kSecClassCertificate, t.kSec.kSecClassGenericPassword, t.kSec.kSecClassInternetPassword ], i = function() {
  function o() {}
  return o.prototype.empty = function() {
    var e = r.alloc().init();
    s.forEach(function(o) {
      e.setObject_forKey_(o, t.kSec.kSecClass), c.SecItemDelete(e);
    });
  }, o.prototype.list = function() {
    var o = this, a = r.alloc().init();
    return a.setObject_forKey_(c.kCFBooleanTrue, t.kSec.kSecReturnAttributes), a.setObject_forKey_(c.kCFBooleanTrue, t.kSec.kSecReturnData), 
    a.setObject_forKey_(c.kCFBooleanTrue, t.kSec.kSecReturnRef), a.setObject_forKey_(t.kSec.kSecMatchLimitAll, t.kSec.kSecMatchLimit), 
    [].concat.apply([], s.map(function(r) {
      var s = [];
      a.setObject_forKey_(r, t.kSec.kSecClass);
      var i = Memory.alloc(Process.pointerSize);
      if (c.SecItemCopyMatching(a, i).isNull()) {
        var n = new ObjC.Object(Memory.readPointer(i));
        if (!(n.length <= 0)) {
          for (var _ = 0; _ < n.count(); _++) {
            var k = n.objectAtIndex_(_);
            s.push({
              item_class: r,
              create_date: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrCreationDate)),
              modification_date: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrModificationDate)),
              description: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrDescription)),
              comment: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrComment)),
              creator: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrCreator)),
              type: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrType)),
              script_code: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrScriptCode)),
              alias: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrAlias)),
              invisible: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrIsInvisible)),
              negative: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrIsNegative)),
              custom_icon: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrHasCustomIcon)),
              protected: e.data_to_string(k.objectForKey_(t.kSec.kSecProtectedDataItemAttr)),
              access_control: k.containsKey_(t.kSec.kSecAttrAccessControl) ? o.decode_acl(k) : "",
              accessible_attribute: t.kSec[k.objectForKey_(t.kSec.kSecAttrAccessible)],
              entitlement_group: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrAccessGroup)),
              generic: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrGeneric)),
              service: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrService)),
              account: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrAccount)),
              label: e.data_to_string(k.objectForKey_(t.kSec.kSecAttrLabel)),
              data: e.data_to_string(k.objectForKey_(t.kSec.kSecValueData))
            });
          }
          return s;
        }
      }
    }).filter(function(e) {
      return void 0 != e;
    }));
  }, o.prototype.decode_acl = function(o) {
    var r = new ObjC.Object(c.SecAccessControlGetConstraints(o.objectForKey_(t.kSec.kSecAttrAccessControl)));
    if (r.handle.isNull()) return "";
    for (var a, s = [], i = r.keyEnumerator(); null !== (a = i.nextObject()); ) {
      var n = r.objectForKey_(a);
      switch (e.data_to_string(a)) {
       case "dacl":
        break;

       case "osgn":
        s.push("kSecAttrKeyClassPrivate");

       case "od":
        for (var _ = n, k = _.keyEnumerator(), S = void 0; null !== (S = k.nextObject()); ) switch (e.data_to_string(S)) {
         case "cpo":
          s.push("kSecAccessControlUserPresence");
          break;

         case "cup":
          s.push("kSecAccessControlDevicePasscode");
          break;

         case "pkofn":
          1 == _.objectForKey_("pkofn") ? s.push("Or") : s.push("And");
          break;

         case "cbio":
          1 == _.objectForKey_("cbio").count() ? s.push("kSecAccessControlBiometryAny") : s.push("kSecAccessControlBiometryCurrentSet");
        }
        break;

       case "prp":
        s.push("kSecAccessControlApplicationPassword");
      }
    }
    return "";
  }, o;
}();

exports.IosKeychain = i;

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
exports.kCFBooleanTrue = ObjC.classes.__NSCFBoolean.numberWithBool_(!0);

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJzcmMvaW5kZXgudHMiLCJzcmMvaW9zL2tleWNoYWluLnRzIiwic3JjL2xpYi9pb3MvY29uc3RhbnRzLnRzIiwic3JjL2xpYi9pb3MvaGVscGVycy50cyIsInNyYy9saWIvaW9zL2xpYmlvcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7OztBQ0FBLElBQUEsSUFBQSxRQUFBOztBQUVBLElBQUk7RUFDQSxjQUFjO0lBQU0sT0FBQSxJQUFLLEVBQUEsY0FBYTs7RUFDdEMsZUFBZTtJQUFNLE9BQUEsSUFBSyxFQUFBLGNBQWE7Ozs7Ozs7Ozs7O0FDRjNDLElBQUEsSUFBQSxRQUFBLHVCQUNBLElBQUEsUUFBQSx5QkFFQSxJQUFBLFFBQUEsc0JBUU0sSUFBQSxLQUFBLFNBQUUsSUFBQSxFQUFBLHFCQUFxQixJQUFBLEVBQUEsVUFHdkIsTUFDRixFQUFBLEtBQUssY0FDTCxFQUFBLEtBQUssbUJBQ0wsRUFBQSxLQUFLLHNCQUNMLEVBQUEsS0FBSywwQkFDTCxFQUFBLEtBQUssNkJBSVQsSUFBQTtFQUFBLFNBQUE7RUFpS0EsT0EvSkksRUFBQSxVQUFBLFFBQUE7SUFHSSxJQUFNLElBQW9CLEVBQW9CLFFBQVE7SUFFdEQsRUFBYSxRQUFRLFNBQUE7TUFHakIsRUFBa0Isa0JBQWtCLEdBQVksRUFBQSxLQUFLLFlBR3JELEVBQUEsY0FBYzs7S0FNdEIsRUFBQSxVQUFBLE9BQUE7SUFBQSxJQUFBLElBQUEsTUFHVSxJQUFvQixFQUFvQixRQUFRO0lBNkR0RCxPQTVEQSxFQUFrQixrQkFBa0IsRUFBQSxnQkFBZ0IsRUFBQSxLQUFLLHVCQUN6RCxFQUFrQixrQkFBa0IsRUFBQSxnQkFBZ0IsRUFBQSxLQUFLO0lBQ3pELEVBQWtCLGtCQUFrQixFQUFBLGdCQUFnQixFQUFBLEtBQUssZ0JBQ3pELEVBQWtCLGtCQUFrQixFQUFBLEtBQUssbUJBQW1CLEVBQUEsS0FBSztPQUVuQixPQUFPLFVBQVUsRUFBYSxJQUFJLFNBQUE7TUFFNUUsSUFBSTtNQUVKLEVBQWtCLGtCQUFrQixHQUFZLEVBQUEsS0FBSztNQUdyRCxJQUFJLElBQWlDLE9BQU8sTUFBTSxRQUFRO01BSTFELElBSGtDLEVBQUEsb0JBQW9CLEdBQW1CLEdBR3ZELFVBQWxCO1FBR0EsSUFBSSxJQUErQixJQUFJLEtBQUssT0FBTyxPQUFPLFlBQVk7UUFJdEUsTUFBSSxFQUFlLFVBQVUsSUFBN0I7VUFJQSxLQUFLLElBQUksSUFBWSxHQUFHLElBQUksRUFBZSxTQUFTLEtBQUs7WUFFckQsSUFBSSxJQUFxQixFQUFlLGVBQWU7WUFFdkQsRUFBaUI7Y0FDYixZQUFZO2NBQ1osYUFBYSxFQUFBLGVBQWUsRUFBSyxjQUFjLEVBQUEsS0FBSztjQUNwRCxtQkFBbUIsRUFBQSxlQUFlLEVBQUssY0FBYyxFQUFBLEtBQUs7Y0FDMUQsYUFBYSxFQUFBLGVBQWUsRUFBSyxjQUFjLEVBQUEsS0FBSztjQUNwRCxTQUFTLEVBQUEsZUFBZSxFQUFLLGNBQWMsRUFBQSxLQUFLO2NBQ2hELFNBQVMsRUFBQSxlQUFlLEVBQUssY0FBYyxFQUFBLEtBQUs7Y0FDaEQsTUFBTSxFQUFBLGVBQWUsRUFBSyxjQUFjLEVBQUEsS0FBSztjQUM3QyxhQUFhLEVBQUEsZUFBZSxFQUFLLGNBQWMsRUFBQSxLQUFLO2NBQ3BELE9BQU8sRUFBQSxlQUFlLEVBQUssY0FBYyxFQUFBLEtBQUs7Y0FDOUMsV0FBVyxFQUFBLGVBQWUsRUFBSyxjQUFjLEVBQUEsS0FBSztjQUNsRCxVQUFVLEVBQUEsZUFBZSxFQUFLLGNBQWMsRUFBQSxLQUFLO2NBQ2pELGFBQWEsRUFBQSxlQUFlLEVBQUssY0FBYyxFQUFBLEtBQUs7Y0FDcEQsV0FBVyxFQUFBLGVBQWUsRUFBSyxjQUFjLEVBQUEsS0FBSztjQUNsRCxnQkFBaUIsRUFBSyxhQUFhLEVBQUEsS0FBSyx5QkFBMEIsRUFBSyxXQUFXLEtBQVE7Y0FDMUYsc0JBQXNCLEVBQUEsS0FBSyxFQUFLLGNBQWMsRUFBQSxLQUFLO2NBQ25ELG1CQUFtQixFQUFBLGVBQWUsRUFBSyxjQUFjLEVBQUEsS0FBSztjQUMxRCxTQUFTLEVBQUEsZUFBZSxFQUFLLGNBQWMsRUFBQSxLQUFLO2NBQ2hELFNBQVMsRUFBQSxlQUFlLEVBQUssY0FBYyxFQUFBLEtBQUs7Y0FDaEQsU0FBUyxFQUFBLGVBQWUsRUFBSyxjQUFjLEVBQUEsS0FBSztjQUNoRCxPQUFPLEVBQUEsZUFBZSxFQUFLLGNBQWMsRUFBQSxLQUFLO2NBQzlDLE1BQU0sRUFBQSxlQUFlLEVBQUssY0FBYyxFQUFBLEtBQUs7OztVQUlyRCxPQUFPOzs7T0FFUixPQUFPLFNBQUE7TUFBSyxZQUFLLEtBQUw7O0tBU1gsRUFBQSxVQUFBLGFBQVIsU0FBbUI7SUFFZixJQUFNLElBQWtCLElBQUksS0FBSyxPQUM3QixFQUFBLCtCQUErQixFQUFNLGNBQWMsRUFBQSxLQUFLO0lBRzVELElBQUksRUFBZ0IsT0FBTyxVQUFZLE9BQU87SUFNOUMsS0FKQSxJQUVJLEdBRkEsUUFDQSxJQUEwQyxFQUFnQixpQkFHZ0IsVUFBdEUsSUFBMEIsRUFBMEIsaUJBQXdCO01BRWhGLElBQUksSUFBb0MsRUFBZ0IsY0FBYztNQUV0RSxRQUFRLEVBQUEsZUFBZTtPQUduQixLQUFLO1FBQ0Q7O09BRUosS0FBSztRQUNELEVBQU0sS0FBSzs7T0FFZixLQUFLO1FBS0QsS0FKQSxJQUFJLElBQTRCLEdBQzVCLElBQXdCLEVBQVksaUJBQ3BDLFNBQW1CLEdBRStDLFVBQTlELElBQXNCLEVBQXNCLGlCQUVoRCxRQUFRLEVBQUEsZUFBZTtTQUNuQixLQUFLO1VBQ0QsRUFBTSxLQUFLO1VBQ1g7O1NBRUosS0FBSztVQUNELEVBQU0sS0FBSztVQUNYOztTQUVKLEtBQUs7VUFDcUMsS0FBdEMsRUFBWSxjQUFjLFdBQ3RCLEVBQU0sS0FBSyxRQUNYLEVBQU0sS0FBSztVQUNmOztTQUVKLEtBQUs7VUFDNEMsS0FBN0MsRUFBWSxjQUFjLFFBQVEsVUFDOUIsRUFBTSxLQUFLLGtDQUNYLEVBQU0sS0FBSzs7UUFRM0I7O09BRUosS0FBSztRQUNELEVBQU0sS0FBSzs7O0lBUXZCLE9BQU87S0FFZjs7O0FBakthLFFBQUEsY0FBQTs7Ozs7Ozs7O0FDdkJiLElBQVk7O0NBQVosU0FBWTtFQUVSLEVBQUEsdUJBQUEsZ0JBQ0EsRUFBQSxpQkFBQSxVQUNBLEVBQUEsZ0JBQUE7RUFDQSxFQUFBLGlCQUFBLFdBQ0EsRUFBQSxvQkFBQSxjQUNBLEVBQUEsWUFBQTtFQUNBLEVBQUEsZUFBQSxRQUNBLEVBQUEsb0JBQUEsUUFDQSxFQUFBLHVCQUFBO0VBQ0EsRUFBQSwyQkFBQSxRQUNBLEVBQUEsNEJBQUEsUUFDQSxFQUFBLGtCQUFBO0VBQ0EsRUFBQSxrQkFBQSxRQUNBLEVBQUEsc0JBQUEsUUFDQSxFQUFBLGdCQUFBO0VBQ0EsRUFBQSx1QkFBQSxRQUNBLEVBQUEsd0JBQUEsUUFDQSxFQUFBLGtCQUFBO0VBQ0EsRUFBQSx5QkFBQSxRQUNBLEVBQUEsMkJBQUEsUUFDQSxFQUFBLGlCQUFBO0VBQ0EsRUFBQSxzQkFBQSxRQUNBLEVBQUEsa0JBQUEsUUFDQSxFQUFBLGtCQUFBO0VBQ0EsRUFBQSxlQUFBLFFBQ0EsRUFBQSxxQkFBQSxRQUNBLEVBQUEsZ0JBQUE7RUFDQSxFQUFBLHNCQUFBLFFBQ0EsRUFBQSxxQkFBQSxRQUNBLEVBQUEsd0JBQUE7RUFDQSxFQUFBLDRCQUFBLFFBQ0EsRUFBQSxxQkFBQSxRQUNBLEVBQUEsaUNBQUE7RUFDQSxFQUFBLHFDQUFBLE1BQ0EsRUFBQSwyQkFBQTtFQUNBLEVBQUEsK0NBQUEsT0FDQSxFQUFBLGtEQUFBO0VBQ0EsRUFBQSxtREFBQSxPQUNBLEVBQUEseUNBQUE7RUFDQSxFQUFBLGdCQUFBO0VBekNRLElBQUEsUUFBQSxTQUFBLFFBQUE7Ozs7O0FDQVosU0FBQSxFQUErQjtFQUUzQjtJQUVJLElBQU0sSUFBWSxJQUFJLEtBQUssT0FBTztJQUNsQyxPQUFPLE9BQU8sZUFBZSxFQUFLLFNBQVMsRUFBSztJQUVsRCxPQUFPO0lBRUw7TUFDSSxPQUFPLEVBQUk7TUFDYixPQUFPO01BQ0wsT0FBTzs7Ozs7OztJQVpuQixRQUFBLGlCQUFBOzs7Ozs7O0lDQ2EsUUFBQSxzQkFBMkIsSUFBSSxlQUN4QyxPQUFPLGlCQUFpQixZQUFZLHdCQUNwQyxhQUFZLFdBQVc7QUFFZCxRQUFBLGlDQUFzQyxJQUFJLGVBQ25ELE9BQU8saUJBQWlCLFlBQVksbUNBQ3BDLGFBQVk7QUFFSCxRQUFBLGdCQUFxQixJQUFJLGVBQ2xDLE9BQU8saUJBQWlCLFlBQVksa0JBQ3BDLGFBQVk7QUFHSCxRQUFBLGlCQUEwQixLQUFLLFFBQVEsY0FBYyxpQkFBZ0IiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiJ9
