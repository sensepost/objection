import { colors as c } from "../lib/color";
import { IJob } from "../lib/interfaces";
import { jobs } from "../lib/jobs";

// Attempts to disable Jailbreak detection.
// This seems like an odd thing to do on a device that is probably not
// jailbroken. However, in the case of a device losing a jailbreak due to
// an OS upgrade, some filesystem artifacts may still exist, causing some
// of the typical checks to incorrectly detect the jailbreak status!

// Hook NSFileManager calls and check if it is to a common path.
// TODO: Hook fopen too.
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
  "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
  "/Library/MobileSubstrate/MobileSubstrate.dylib",
  "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
  "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
  "/bin/bash",
  "/bin/sh",
  "/etc/apt",
  "/etc/ssh/sshd_config",
  "/private/var/stash",
  "/private/var/tmp/cydia.log",
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

export namespace iosjailbreak {

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
            case(true):
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

            case(false):
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

  const libSystemBFork = (success: boolean, ident: string): InvocationListener => {
    // Hook fork() in libSystem.B.dylib and return 0
    // TODO: Hook vfork
    const libSystemBdylibFork: NativePointer = Module.findExportByName("libSystem.B.dylib", "fork");

    // iOS simulator does not have libSystem.B.dylib
    // TODO: Remove as iOS 12 similar may have this now.
    if (! libSystemBdylibFork) {
      return new InvocationListener();
    }

    return Interceptor.attach(libSystemBdylibFork, {
      onLeave(retval) {

        switch (success) {
          case(true):
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

          case(false):
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

  export const disable = (): void => {
    const job: IJob = {
      identifier: jobs.identifier(),
      invocations: [],
      type: "ios-jailbreak-disable",
    };

    job.invocations.push(fileExistsAtPath(false, job.identifier));
    job.invocations.push(libSystemBFork(false, job.identifier));

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

    jobs.add(job);
  };
}
