import { colors as c } from "../lib/color.js";
import { IJob } from "../lib/interfaces.js";
import * as jobs from "../lib/jobs.js";

// Attempts to disable Jailbreak detection.
// This seems like an odd thing to do on a device that is probably not
// jailbroken. However, in the case of a device losing a jailbreak due to
// an OS upgrade, some filesystem artifacts may still exist, causing some
// of the typical checks to incorrectly detect the jailbreak status!

// Hook NSFileManager and fopen calls and check if it is to a common path.
// Hook canOpenURL for Cydia deep link.

const jailbreakPaths = [
  "/Applications/Cydia.app",
  "/Applications/FakeCarrier.app",
  "/Applications/Icy.app",
  "/Applications/IntelliScreen.app",
  "/Applications/MxTube.app",
  "/Applications/RockApp.app",
  "/Applications/SBSetttings.app",
  "/Applications/WinterBoard.app",
  "/Applications/blackra1n.app",
  "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
  "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
  "/Library/MobileSubstrate/MobileSubstrate.dylib",
  "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
  "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
  "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
  "/bin/bash",
  "/bin/sh",
  "/etc/apt",
  "/etc/ssh/sshd_config",
  "/private/var/stash",
  "/private/var/tmp/cydia.log",
  "/private/var/lib/apt",
  "/usr/bin/cycript",
  "/usr/bin/ssh",
  "/usr/bin/sshd",
  "/usr/libexec/sftp-server",
  "/usr/libexec/sftp-server",
  "/usr/libexec/ssh-keysign",
  "/usr/sbin/sshd",
  "/var/cache/apt",
  "/var/lib/cydia",
  "/var/log/syslog",
  "/var/tmp/cydia.log",
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
  const fopen_addr = Module.findExportByName(null, "fopen");
  if (!fopen_addr) {
    send(c.red(`fopen function not found!`));
    return new InvocationListener(); 
  }

  return Interceptor.attach(fopen_addr, {
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

// toggles replies to canOpenURL for Cydia
const canOpenURL = (success: boolean, ident: string): InvocationListener => {

  return Interceptor.attach(
    ObjC.classes.UIApplication["- canOpenURL:"].implementation, {
    onEnter(args) {

      this.is_flagged = false;

      // Extract the path
      this.path = new ObjC.Object(args[2]).toString();

      if (this.path.startsWith('cydia') || this.path.startsWith('Cydia')) {
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
  // Hook fork() in libSystem.B.dylib and return 0
  // TODO: Hook vfork
  const libSystemBdylibFork = Module.findExportByName("libSystem.B.dylib", "fork");

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
          if (retval.isNull()) {
            return;
          }
          send(
            c.blackBright(`[${ident}] `) + `Call to ` +
            c.green(`libSystem.B.dylib::fork()`) + ` was successful with ` +
            c.red(retval.toString()) + ` marking it as failed.`,
          );

          retval.replace(new NativePointer(0x0));
          break;
      }
    },
  });
};

// ref: https://www.ayrx.me/gantix-jailmonkey-root-detection-bypass/
const jailMonkeyBypass = (success: boolean, ident: string): InvocationListener => {
  const JailMonkeyClass = ObjC.classes.JailMonkey;
  if (JailMonkeyClass === undefined) return new InvocationListener();

  return Interceptor.attach(JailMonkeyClass["- isJailBroken"].implementation, {
    onLeave(retval) {
      send(
        c.blackBright(`[${ident}] `) + `JailMonkey.isJailBroken called, returning false.`
      );
      retval.replace(new NativePointer(0x00));
    }
  });
};

export const disable = (): void => {
  const job: IJob = {
    identifier: jobs.identifier(),
    type: "ios-jailbreak-disable",
  };

  job.invocations = [];

  job.invocations.push(fileExistsAtPath(false, job.identifier));
  job.invocations.push(libSystemBFork(false, job.identifier));
  job.invocations.push(fopen(false, job.identifier));
  job.invocations.push(canOpenURL(false, job.identifier));
  job.invocations.push(jailMonkeyBypass(false, job.identifier));

  jobs.add(job);
};

export const enable = (): void => {
  const job: IJob = {
    identifier: jobs.identifier(),
    type: "ios-jailbreak-enable",
  };

  job.invocations = [];

  job.invocations.push(fileExistsAtPath(true, job.identifier));
  job.invocations.push(libSystemBFork(true, job.identifier));
  job.invocations.push(fopen(true, job.identifier));
  job.invocations.push(canOpenURL(true, job.identifier));
  job.invocations.push(jailMonkeyBypass(true, job.identifier));

  jobs.add(job);
};
