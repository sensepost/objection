import { colors as c } from "../lib/color";
import { IJob } from "../lib/interfaces";
import * as jobs from "../lib/jobs";

// Attempts to disable Jailbreak detection.
// This seems like an odd thing to do on a device that is probably not
// jailbroken. However, in the case of a device losing a jailbreak due to
// an OS upgrade, some filesystem artifacts may still exist, causing some
// of the typical checks to incorrectly detect the jailbreak status!

// Hook NSFileManager and fopen calls and check if it is to a common path.
// Hook canOpenURL for Cydia and other common deep link.

const jailbreakPaths = [
  "/.bootstrapped_electra",
  "/.cydia_no_stash",
  "/.installed_unc0ver",
  "/Applications/Cydia.app",
  "/Applications/FakeCarrier.app",
  "/Applications/FlyJB.app",
  "/Applications/Icy.app",
  "/Applications/IntelliScreen.app",
  "/Applications/MxTube.app",
  "/Applications/RockApp.app",
  "/Applications/SBSettings.app",
  "/Applications/Sileo.app",
  "/Applications/Electra.app",
  "/Applications/unc0ver.app",
  "/Applications/Xabsi.app",
  "/Applications/zJailbreak.app",
  "/Applications/Pangu.app",
  "/Applications/Chimera.app",
  "/Applications/WinterBoard.app",
  "/Applications/Zebra.app",
  "/Applications/blackra1n.app",
  "/Library/MobileSubstrate/CydiaSubstrate.dylib",
  "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
  "/Library/MobileSubstrate/DynamicLibraries/zzzzLiberty.dylib",
  "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
  "/Library/MobileSubstrate/MobileSubstrate.dylib",
  "/Library/PreferenceBundles/ABypassPrefs.bundle",
  "/Library/PreferenceBundles/FlyJBPrefs.bundle",
  "/Library/PreferenceBundles/LibertyPref.bundle",
  "/Library/PreferenceBundles/ShadowPreferences.bundle",
  "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
  "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
  "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
  "/bin/bash",
  "/bin/sh",
  "/etc/apt",
  "/etc/apt/sources.list.d/electra.list",
  "/etc/apt/sources.list.d/sileo.sources",
  "/etc/apt/undecimus/undecimus.list",
  "/etc/clutch.conf",
  "/etc/clutch_cracked.plist",
  "/etc/ssh/sshd_config",
  "/jb/amfid_payload.dylib",
  "/jb/jailbreakd.plist",
  "/jb/libjailbreak.dylib",
  "/jb/lzma",
  "/jb/offsets.plist",
  "/private/var/Users/",
  "/private/var/cache/apt",
  "/private/var/cache/apt/",
  "/private/var/lib/apt",
  "/private/var/lib/apt/",
  "/private/var/lib/cydia",
  "/private/var/log/syslog",
  "/private/var/mobile/Library/SBSettings/Themes",
  "/private/var/stash",
  "/private/var/tmp/cydia.log",
  "/usr/bin/cycript",
  "/usr/bin/frida-server",
  "/usr/bin/ssh",
  "/usr/bin/sshd",
  "/usr/lib/ABDYLD.dylib",
  "/usr/lib/ABSubLoader.dylib",
  "/usr/lib/TweakInject",
  "/usr/lib/libcycript.dylib",
  "/usr/lib/libhooker.dylib",
  "/usr/lib/libjailbreak.dylib",
  "/usr/lib/libsubstitute.dylib",
  "/usr/lib/substrate",
  "/usr/libexec/cydia/firmware.sh",
  "/usr/libexec/sftp-server",
  "/usr/libexec/ssh-keysign",
  "/usr/local/bin/cycript",
  "/usr/sbin/frida-server",
  "/usr/sbin/sshd",
  "/usr/share/jailbreak/injectme.plist",
  "/var/binpack",
  "/var/binpack/Applications/loader.app",
  "/var/cache/apt",
  "/var/cache/clutch.plist",
  "/var/cache/clutch_cracked.plist",
  "/var/lib/clutch/overdrive.dylib",
  "/var/lib/cydia",
  "/var/lib/dpkg/info/mobilesubstrate.md5sums",
  "/var/log/apt",
  "/var/log/syslog",
  "/var/mobile/Library/Preferences/ABPattern",
  "/var/root/Documents/Cracked/",
  "/var/tmp/cydia.log",
];

const tamperLibs = [
  "ABypass",
  "Cephei",
  "CustomWidgetIcons",
  "cycript",
  "CydiaSubstrate",
  "cynject",
  "Electra",
  "FlyJB",
  "frida",
  "FridaGadget",
  "libcycrypt",
  "libhooker",
  "libsubstitute.dylib",
  "MobileSubstrate.dylib",
  "PreferenceLoader",
  "RocketBootstrap",
  "SSLKillSwitch",
  "SSLKillSwitch.dylib",
  "SSLKillSwitch2",
  "SSLKillSwitch2.dylib",
  "Substitute",
  "substitute-loader.dylib",
  "Substrate",
  "SubstrateBootstrap",
  "SubstrateBootstrap.dylib",
  "SubstrateInserter",
  "SubstrateInserter.dylib",
  "SubstrateLoader.dylib",
  "TweakInject.dylib",
  "WeeLoader",
];

const urlSchemes = [
  "undecimus",
  "sileo",
  "zbra",
  "filza",
  "activator",
  "cydia",
];

const writableDirs = [
"/",
"/root/",
"/private/",
"/jb/",
];

const symLinkPaths = [
"/Applications",
"/var/lib/undecimus/apt",
"/var/stash/Library/Ringtones",
"/var/stash/Library/Wallpaper",
"/var/stash/usr/arm-apple-darwin9",
"/var/stash/usr/include",
"/var/stash/usr/libexec",
"/var/stash/usr/share",
"/Library/Ringtones",
"/Library/Wallpaper",
"/usr/arm-apple-darwin9",
"/usr/include",
"/usr/libexec",
"/usr/share",
];

const processNames = [
  "MobileCydia",
  "Cydia",
  "afpd",
];

// toggles replies to fileExistsAtPath: for the paths in jailbreakPaths
const fileExistsAtPath = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    ObjC.classes.NSFileManager["- fileExistsAtPath:"].implementation, {
    onEnter(args) {

      // Use a marker to check onExit if we need to manipulate
      // the response.
      this.is_common_path = false;

      // Extract the path
      this.path = new ObjC.Object(args[2]).toString();

      // check if the looked up path is in the list of common_paths
      if (jailbreakPaths.indexOf(this.path) >= 0) {

        // Mark this path as one that should have its response
        // modified if needed.
        this.is_common_path = true;
      }
    },
    onLeave(retval) {

      // stop if we dont care about the path
      if (!this.is_common_path) {
        return;
      }

      // depending on the desired state, we flip retval
      switch (success) {
        case (true):
          // ignore successful lookups
          if (!retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `fileExistsAtPath: check for ` +
            c.green(this.path) + ` failed with: ` +
            c.red(retval.toString()) + `, marking it as successful.`,
          );

          retval.replace(new NativePointer(0x01));
          break;

        case (false):
          // ignore failed lookups
          if (retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `fileExistsAtPath: check for ` +
            c.green(this.path) + ` was successful with: ` +
            c.red(retval.toString()) + `, marking it as failed.`,
          );

          retval.replace(new NativePointer(0x00));
          break;
      }
    },
  },
  );
};


// toggles replies to fopen: for the paths in jailbreakPaths
const fopen = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    Module.findExportByName(null, "fopen"), {
    onEnter(args) {

      this.is_common_path = false;

      // Extract the path
      this.path = args[0].readCString();

      // check if the looked up path is in the list of common_paths
      if (jailbreakPaths.indexOf(this.path) >= 0) {

        // Mark this path as one that should have its response
        // modified if needed.
        this.is_common_path = true;
      }
    },
    onLeave(retval) {

      // stop if we dont care about the path
      if (!this.is_common_path) {
        return;
      }

      // depending on the desired state, we flip retval
      switch (success) {
        case (true):
          // ignore successful lookups
          if (!retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `fopen: check for ` +
            c.green(this.path) + ` failed with: ` +
            c.red(retval.toString()) + `, marking it as successful.`,
          );

          retval.replace(new NativePointer(0x01));
          break;

        case (false):
          // ignore failed lookups
          if (retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `fopen: check for ` +
            c.green(this.path) + ` was successful with: ` +
            c.red(retval.toString()) + `, marking it as failed.`,
          );

          retval.replace(new NativePointer(0x00));
          break;
      }
    },
  },
  );
};

// toggles replies to canOpenURL for url schems in urlSchemes
const canOpenURL = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    ObjC.classes.UIApplication["- canOpenURL:"].implementation, {
    onEnter(args) {

      this.is_flagged = false;

      // Extract the path
      this.path = new ObjC.Object(args[2]).toString();

      //if (this.path.startsWith('cydia') || this.path.startsWith('Cydia')) {
        // Changed to look for multiple URL Schemes
        if (this.path.startsWith(urlSchemes.indexOf(this.path)) >= 0) {
          
          this.is_flagged = true;
      }
    },
    onLeave(retval) {

      if (!this.is_flagged) {
        return;
      }

      // depending on the desired state, we flip retval
      switch (success) {
        case (true):
          // ignore successful lookups
          if (!retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `canOpenURL: check for ` +
            c.green(this.path) + ` failed with: ` +
            c.red(retval.toString()) + `, marking it as successful.`,
          );

          retval.replace(new NativePointer(0x01));
          break;

        case (false):
          // ignore failed
          if (retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `canOpenURL: check for ` +
            c.green(this.path) + ` was successful with: ` +
            c.red(retval.toString()) + `, marking it as failed.`,
          );

          retval.replace(new NativePointer(0x00));
          break;
      }
    },
  },
  );
};

const libSystemBFork = (success: boolean, ident: string): InvocationListener => {
  // Hook fork() in libSystem.B.dylib and return -1
  // TODO: Hook vfork
  // TODO: Hook posix_spawn
  const libSystemBdylibFork: NativePointer = Module.findExportByName("libSystem.B.dylib", "fork");

  // iOS simulator does not have libSystem.B.dylib
  // TODO: Remove as iOS 12 similar may have this now.
  if (!libSystemBdylibFork) {
    return new InvocationListener();
  }

  return Interceptor.attach(libSystemBdylibFork, {
    onLeave(retval) {

      switch (success) {
        case (true):
          // already successful forks are ok
          if (!retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `Call to ` +
            c.green(`libSystem.B.dylib::fork()`) + ` failed with ` +
            c.red(retval.toString()) + ` marking it as successful.`,
          );

          retval.replace(new NativePointer(0x1));
          break;

        case (false):
          // already failed forks are ok
          if (retval.equals(0xffffffff)) { // -1 is a failed fork so we should check for it rather than null here
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `Call to ` +
            c.green(`libSystem.B.dylib::fork()`) + ` was successful with ` +
            c.red(retval.toString()) + ` marking it as failed.`,
          );
            // fork should return a negative to bypass the check
          retval.replace(new NativePointer(0xffffffff));
          break;
      }
    },
  });
};

// ref: https://www.ayrx.me/gantix-jailmonkey-root-detection-bypass/
const jailMonkeyBypass = (success: boolean, ident: string): InvocationListener => {
  const JailMonkeyClass = ObjC.classes.JailMonkey;
  if (JailMonkeyClass === undefined) return null;

  return Interceptor.attach(JailMonkeyClass["- isJailBroken"].implementation, {
    onLeave(retval) {
      send(
        c.blackBright(`[${ident}] `) + `JailMonkey.isJailBroken called, returning false.`
      );
      retval.replace(new NativePointer(0x00));
    }
  });
};

// disable ptrace
const ptrace = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    Module.findExportByName(null, "ptrace"), {
    onEnter(args) {
      // the first arg is what we need to manipulate
      this.firstArg = args[0];

      if(this.firstArg == 0x1f) {
        send(
          c.blackBright(`[${ident}] `) + `ptrace: check for args ` + 
          c.green(`[` + args[0] + `:` + args[1] + `:` + args[2] + `:` + args[3] + `] `) + `was successful, ` + 
          `marking it failed`
        );
        // the first arg should be 0
        args[0] = new NativePointer(0x00);
      }
    }
  }
)};

// disable getppid
const getppid = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    Module.findExportByName(null, "getppid"), {
    onLeave(retval) {
      send(
        c.blackBright(`[${ident}] `) + `getppid called, returning true.`
      );
      // should always return 1 as the parent process
      retval.replace(new NativePointer(0x01));
    }
  }
)};

// disable dladdr - needs more testing
const dladdr = (success: boolean, ident: string): InvocationListener => {

    return Interceptor.attach(
      Module.findExportByName(null, "dladdr"), {
        onEnter(args){
            send(
                c.blackBright(`[${ident}] `) + `dladdr called.`
              );
        },
      onLeave(retval) {
        send(
          c.blackBright(`[${ident}] `) + `dladdr called, returning true.`
        );
        // should always return 1 as the parent process
        retval.replace(new NativePointer(0x00));
      }
    }
  )};

// toggles replies to strstr: for the paths in tamperLibs
const strstr = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    Module.findExportByName(null, "strstr"), {
    onEnter(args) {

      this.is_common_path = false;

      // Extract the path
      this.path = args[1].readUtf8String();

      // check if the looked up path is in the list of tamperLibs
      if (tamperLibs.indexOf(this.path) >= 0) {

        // Mark this path as one that should have its response
        // modified if needed.
        this.is_common_path = true;
      }
    },
    onLeave(retval) {

      // stop if we dont care about the path
      if (!this.is_common_path) {
        return;
      }

      // depending on the desired state, we flip retval
      switch (success) {
        case (true):
          // ignore successful lookups
          if (!retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `strstr: check for ` +
            c.green(this.path) + ` failed with: ` +
            c.red(retval.toString()) + `, marking it as successful.`,
          );

          retval.replace(new NativePointer(0x01));
          break;

        case (false):
          // ignore failed lookups
          if (retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `strstr: check for ` +
            c.green(this.path) + ` was successful with: ` +
            c.red(retval.toString()) + `, marking it as failed.`,
          );

          retval.replace(new NativePointer(0x00));
          break;
      }
    },
  },
  );
};

// toggle replied to writeToFile for dirs in writableDirs
const writeToFile = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    ObjC.classes.NSString["- writeToFile:atomically:encoding:error:"].implementation, {
    onEnter(args) {

      this.is_common_path = false;

      // Extract the path
      this.path = new ObjC.Object(args[2]).toString();

      if (writableDirs.indexOf(this.path) >= 0) {

        // Mark this path as one that should have its response
        // modified if needed.
        this.is_common_path = true;
      }
    },
    onLeave(retval) {

      if (!this.is_common_path) {
        return;
      }

      // depending on the desired state, we flip retval
      switch (success) {
        case (true):
          // ignore successful lookups
          if (!retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `writeToFile: check for ` +
            c.green(this.path) + ` failed with: ` +
            c.red(retval.toString()) + `, marking it as successful.`,
          );

          retval.replace(new NativePointer(0x01));
          break;

        case (false):
          // ignore failed
          if (retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `writeToFile: check for ` +
            c.green(this.path) + ` was successful with: ` +
            c.red(retval.toString()) + `, marking it as failed.`,
          );

          retval.replace(new NativePointer(0x00));
          break;
      }
    },
  },
  );
};

// toggles replies to stat
const stat = (success: boolean, ident: string): InvocationListener => {
// TODO: hook stat64
  return Interceptor.attach(
    Module.findExportByName(null, "stat"), {
      onEnter(args) {
      
        this.is_common_path = false;

        // Extract the path
        this.path = args[0].readCString();
        
        // stat is used to check fstab size so it should be the only path we care aboot
        if (this.path == "/etc/fstab") {
  
          // Mark this path as one that should have its response
          // modified if needed.
          this.is_common_path = true;
        }
      },
    onLeave(retval) {

      if (this.is_common_path && !retval.equals('-1')) {

        send(
          c.blackBright(`[${ident}] `) + `stat: check for ` +
          c.green(this.path) + ` was successful with: ` +
           c.red(retval.toString()) + `, marking it as failed.`,
         );
         retval.replace(new NativePointer(0xffffffff));   
      }   
    },
  },
  );
};

// toggle replies to libSystem.B.dylib::system
const libSystemBSystem = (success: boolean, ident: string): InvocationListener => {

  const libSystemBdylibSys: NativePointer = Module.findExportByName("libSystem.B.dylib", "system");

  if (!libSystemBdylibSys) {
    return new InvocationListener();
  }

  return Interceptor.attach(libSystemBdylibSys, {
    onLeave(retval) {

      switch (success) {
        case (true):
          // ignore successful lookups
          if (!retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `Call to ` +
            c.green(`libSystem.B.dylib::system()`) + ` failed with ` +
            c.red(retval.toString()) + ` marking it as successful.`,
          );

          retval.replace(new NativePointer(0x1));
          break;

        case (false):
          // ignore failed lookups
          if (retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `Call to ` +
            c.green(`libSystem.B.dylib::system()`) + ` was successful with ` +
            c.red(retval.toString()) + ` marking it as failed.`,
          );

          retval.replace(new NativePointer(0x0));
          break;
      }
    },
  });
};

// toggles replies to isEqualToString: for the paths in processNames
const isEqualToString = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    ObjC.classes.NSString["- isEqualToString:"].implementation, {
    onEnter(args) {

      // Use a marker to check onExit if we need to manipulate
      // the response.
      this.is_common_path = false;

      // Extract the path
      this.path = new ObjC.Object(args[2]).toString();

      // check if the looked up path is in the list of processNames
      if (processNames.indexOf(this.path) >= 0) {

        // Mark this path as one that should have its response
        // modified if needed.
        this.is_common_path = true;
      }
    },
    onLeave(retval) {

      // stop if we dont care about the path
      if (!this.is_common_path) {
        return;
      }

      // depending on the desired state, we flip retval
      switch (success) {
        case (true):
          // ignore successful lookups
          if (!retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `isEqualToString: check for ` +
            c.green(this.path) + ` failed with: ` +
            c.red(retval.toString()) + `, marking it as successful.`,
          );

          retval.replace(new NativePointer(0x01));
          break;

        case (false):
          // ignore failed lookups
          if (retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `isEqualToString: check for ` +
            c.green(this.path) + ` was successful with: ` +
            c.red(retval.toString()) + `, marking it as failed.`,
          );

          retval.replace(new NativePointer(0x00));
          break;
      }
    },
  },
  );
};

// disable access
const access = (success: boolean, ident: string): InvocationListener => {
  return Interceptor.attach(
    Module.findExportByName(null, "access"), {
      onEnter(args) {

        this.is_common_path = false;
  
        // Extract the path
        this.path = args[0].readCString();
  
        // check if the looked up path is in the list of jailbreakPaths
        if (jailbreakPaths.indexOf(this.path) >= 0) {
          // Mark this path as one that should have its response
          // modified if needed.
          this.is_common_path = true;
        }
      },
    onLeave(retval) {
      if(this.is_common_path && retval.equals(0x0)) {
        send(
        c.blackBright(`[${ident}] `) + `access: check for ` +
        c.green(this.path) + ` failed with: ` +
        c.red(retval.toString()) + `, marking it as successful.`,
      );
      // access returns -1 on error
      retval.replace(new NativePointer(0xffffffff));
      }
    }
  }
)};

// check lstat for know libraries
const lstat = (success: boolean, ident: string): InvocationListener => {
  return Interceptor.attach(
    Module.findExportByName(null, "lstat"), {
      onEnter(args) {

        this.is_common_path = false;
  
        // Extract the path
        this.path = args[0].readCString();
  
        // check if the looked up path is in the list of jailbreakPaths
        if (jailbreakPaths.indexOf(this.path) >= 0) {
  
          // Mark this path as one that should have its response
          // modified if needed.
          this.is_common_path = true;
        }
      },
    onLeave(retval) {
      if(this.is_common_path && retval.equals(0x0)) {
        send(
          c.blackBright(`[${ident}] `) + `lstat: check for ` +
          c.green(this.path) + ` was successful with: ` +
          c.red(retval.toString()) + `, marking it as failed.`,
        );
      // lstat returns -1 on error
      retval.replace(new NativePointer(0x0ffffffff));
      }
    }
  }
)};


// toggles replies to _dyld_get_image_name for the paths in tamperLibs
const _dyld_get_image_name = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    Module.findExportByName(null, "_dyld_get_image_name"), {
      
      // We take care of all the logic in the onLeave because the arguments in the onEnter returns null
      onEnter(args) {
        //send(c.blueBright("ENTERED _dyld_get_image_name: " + args[0].readCString()));
      },
    onLeave(retval) {
    
      this.is_common_path = false;

      // Extract the path and split it into an array
      this.path = retval.readCString().split("/");
      
      // Get the array size
      this.size = this.path.length;
      
      // We only care aboot the last element
      this.last = this.path[this.size -1];

      // Check if the looked up path is in the list of tamperLibs
      if (tamperLibs.indexOf(this.last) >= 0) {
        
        // Mark this path as one that should have its response
        // modified if needed.
        this.is_common_path = true;
      }

      // stop if we dont care about the path
      if (!this.is_common_path) {
        return;
      }

      // depending on the desired state, we flip retval
      switch (success) {
        case (true):
          // ignore successful lookups
          if (!retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `_dyld_get_image_name: check for ` +
            c.green(this.last) + ` failed with: ` +
            c.red(retval.readCString()) + `, marking it as successful.`,
          );

            // dont replace retval, let the function do its thing - TODO: replace with a tamperLib to simulate?
          //retval.replace(new NativePointer(0x01));
          break;

        case (false):
          // ignore failed lookups
          if (retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `_dyld_get_image_name: check for ` +
            c.green(this.last) + ` was successful with: ` +
            c.red(retval.readCString()) + `, marking it as failed.`,
          );
          // _dyld_get_image_name expects a string in return, so give it an empty one
          this.replacementString = Memory.allocUtf16String("");
          retval.replace(new NativePointer(this.replacementString));
          break;
      }
    },
  },
  );
};

// _dyld_image_count is used as a counter to loop through suspicious loaded libraries for the above _dyld_get_image_name function
// It is possible to return a 0 to the below function to bypass the above check, however I am not sure if _dyld_image_count is
// used legitimately in other apps, in which case the below bypass cound break applications
// It's probably best to leave this as an 'in case' and not have it enabled until more testing is done
const _dyld_image_count = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    Module.findExportByName(null, "_dyld_image_count"), {
    onEnter(args) {
      send(c.green("_dyld_image_count called with ARGS: "+args));
    },
    onLeave(retval){
      send(c.green("Leaving _dyld_image_count RETVAL: "+retval));    
      retval.replace(new NativePointer(0x00));  
    }
  })
};


// disable sysctl
const sysctl = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    Module.findExportByName(null, "__sysctl"), {
    onEnter(args) {
      //setup for the return value
      this.kinfo = this.context['x2'];
    },
    onLeave(retval) {
      this.p = this.kinfo.add(32);
      //this.p = this.kinfo; // this works without the 'add(32)' in some cases. Perhaps it's just a special case with my test app.
      this.p_flag = this.p.readInt() & 0x800;
      if (this.p_flag === 0x800) {
        send(
          c.blackBright(`[${ident}] `) + `sysctl: check for P value ` +
          c.green(this.p_flag) + ` was successful, ` +
          `marking it as failed.`,
        );
        this.p.writeInt(0);
      }
    },
  },
  );
};

// toggles replies to destinationOfSymbolicLinkAtPath: for the paths in symlinkPaths
const destinationOfSymbolicLink = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    ObjC.classes.NSFileManager["- destinationOfSymbolicLinkAtPath:error:"].implementation, {
    onEnter(args) {

      // Use a marker to check onExit if we need to manipulate
      // the response.
      this.is_common_path = false;

      // Extract the path
      this.path = new ObjC.Object(args[2]).toString();

      // check if the looked up path is in the list of symLinkPaths
      if (symLinkPaths.indexOf(this.path) >= 0) {

        // Mark this path as one that should have its response
        // modified if needed.
        this.is_common_path = true;
      }
    },
    onLeave(retval) {

      // stop if we dont care about the path
      if (!this.is_common_path) {
        return;
      }

      // depending on the desired state, we flip retval
      switch (success) {
        case (true):
          // ignore successful lookups
          if (!retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `destinationOfSymbolicLink: check for ` +
            c.green(this.path) + ` failed with: ` +
            c.red(retval.toString()) + `, marking it as successful.`,
          );

          retval.replace(new NativePointer(0x01));
          break;

        case (false):
          // ignore failed lookups
          if (retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `destinationOfSymbolicLink: check for ` +
            c.green(this.path) + ` was successful with: ` +
            c.red(retval.toString()) + `, marking it as failed.`,
          );

          retval.replace(new NativePointer(0x00));
          break;
      }
    },
  },
  );
};

// toggles replies to isReadableFileAtPath: for the paths in jailbreakPaths
const isReadableFileAtPath = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    ObjC.classes.NSFileManager["- isReadableFileAtPath:"].implementation, {
    onEnter(args) {

      // Use a marker to check onExit if we need to manipulate
      // the response.
      this.is_common_path = false;

      // Extract the path
      this.path = new ObjC.Object(args[2]).toString();

      // check if the looked up path is in the list of jailbreakPaths
      if (jailbreakPaths.indexOf(this.path) >= 0) {

        // Mark this path as one that should have its response
        // modified if needed.
        this.is_common_path = true;
      }
    },
    onLeave(retval) {

      // stop if we dont care about the path
      if (!this.is_common_path) {
        return;
      }

      // depending on the desired state, we flip retval
      switch (success) {
        case (true):
          // ignore successful lookups
          if (!retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `isReadableFileAtPath: check for ` +
            c.green(this.path) + ` failed with: ` +
            c.red(retval.toString()) + `, marking it as successful.`,
          );

          retval.replace(new NativePointer(0x01));
          break;

        case (false):
          // ignore failed lookups
          if (retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `isReadableFileAtPath: check for ` +
            c.green(this.path) + ` was successful with: ` +
            c.red(retval.toString()) + `, marking it as failed.`,
          );

          retval.replace(new NativePointer(0x00));
          break;
      }
    },
  },
  );
};

// bypass frida check for local connection on port 27042 and needle on port 4444 (who uses needle still?)
// TODO: currently only looking for a the IP 127.0.0.1; need to add port check
const inet_addr = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    Module.findExportByName(null, "inet_addr"), {
    onEnter(args) {

      this.is_common_path = false;

      // read the IP address that is being checked
      this.path = args[0].readCString();
      
      if (this.path == '127.0.0.1') {
        console.log("replacing localhost");
        //this.path = '1.1.1.1';
        this.is_common_path = true;
      }

    },
    onLeave(retval) {
      
      // stop if we dont care about the path
      if (!this.is_common_path) {
        return;
      }

      // depending on the desired state, we flip retval
      switch (success) {
        case (true):
          // ignore successful lookups
          if (!retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `inet_addr: check for ` +
            c.green(this.path) + ` failed with: ` +
            c.red(retval.toString()) + `, marking it as successful.`,
          );

          retval.replace(new NativePointer(0x01));
          break;

        case (false):
          // ignore failed lookups
          if (retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `inet_addr: check for ` +
            c.green(this.path) + ` was successful with: ` +
            c.red(retval.toString()) + `, marking it as failed.`,
          );
            // inet_addr returns -1 on error
          retval.replace(new NativePointer(0x200008f));
          console.log(retval.toString());
          break;
      }
    },
  },
  );
};


// TODO: popen; ssh loopback; posix_spawn; dlsym
// TODO: This file is getting large, future me will streamline this file

export const disable = (): void => {
  const job: IJob = {
    identifier: jobs.identifier(),
    invocations: [],
    type: "ios-jailbreak-disable",
  };

  job.invocations.push(fileExistsAtPath(false, job.identifier));
  job.invocations.push(libSystemBFork(false, job.identifier));
  job.invocations.push(fopen(false, job.identifier));
  job.invocations.push(canOpenURL(false, job.identifier));
  job.invocations.push(jailMonkeyBypass(false, job.identifier));
  job.invocations.push(ptrace(false, job.identifier));
  job.invocations.push(getppid(false, job.identifier));
  //job.invocations.push(dladdr(false, job.identifier));
  job.invocations.push(strstr(false, job.identifier));
  job.invocations.push(writeToFile(false, job.identifier));
  job.invocations.push(access(false, job.identifier));
  job.invocations.push(libSystemBSystem(false, job.identifier));
  job.invocations.push(isEqualToString(false, job.identifier));
  job.invocations.push(stat(false, job.identifier));
  job.invocations.push(lstat(false, job.identifier));
  //job.invocations.push(_dyld_image_count(false, job.identifier));
  job.invocations.push(_dyld_get_image_name(false, job.identifier));
  job.invocations.push(sysctl(false, job.identifier));
  job.invocations.push(destinationOfSymbolicLink(false, job.identifier));
  job.invocations.push(isReadableFileAtPath(false, job.identifier));
  job.invocations.push(inet_addr(false, job.identifier));
  jobs.add(job);
};

export const enable = (): void => {
  const job: IJob = {
    identifier: jobs.identifier(),
    invocations: [],
    type: "ios-jailbreak-enable",
  };

  job.invocations.push(fileExistsAtPath(true, job.identifier));
  job.invocations.push(libSystemBFork(true, job.identifier));
  job.invocations.push(fopen(true, job.identifier));
  job.invocations.push(canOpenURL(true, job.identifier));
  job.invocations.push(jailMonkeyBypass(true, job.identifier));
  job.invocations.push(ptrace(true, job.identifier));
  job.invocations.push(getppid(true, job.identifier));
  job.invocations.push(strstr(true, job.identifier));
  job.invocations.push(writeToFile(true, job.identifier));
  job.invocations.push(access(true, job.identifier));
  job.invocations.push(libSystemBSystem(true, job.identifier));
  job.invocations.push(isEqualToString(true, job.identifier));
  job.invocations.push(stat(true, job.identifier));
  job.invocations.push(lstat(true, job.identifier));
  job.invocations.push(_dyld_get_image_name(true, job.identifier));
  job.invocations.push(sysctl(true, job.identifier));
  job.invocations.push(destinationOfSymbolicLink(true, job.identifier));
  job.invocations.push(isReadableFileAtPath(true, job.identifier));
  job.invocations.push(inet_addr(true, job.identifier));

  jobs.add(job);
};