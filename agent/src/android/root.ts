import { colors as c } from "../lib/color";
import { IJob } from "../lib/interfaces";
import { jobs } from "../lib/jobs";
import { wrapJavaPerform } from "./lib/libjava";
import { File, IOException, JavaString, Runtime } from "./lib/types";

export namespace root {
  const commonPaths = [
    "/data/local/bin/su",
    "/data/local/su",
    "/data/local/xbin/su",
    "/dev/com.koushikdutta.superuser.daemon/",
    "/sbin/su",
    "/system/app/Superuser.apk",
    "/system/bin/failsafe/su",
    "/system/bin/su",
    "/system/etc/init.d/99SuperSUDaemon",
    "/system/sd/xbin/su",
    "/system/xbin/busybox",
    "/system/xbin/daemonsu",
    "/system/xbin/su",
  ];

  const testKeysCheck = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const JavaString: JavaString = Java.use("java.lang.String");
      JavaString.contains.implementation = function (name) {
        if (name !== "test-keys") {
          return this.contains.call(this, name);
        }

        if (success) {
          send(c.blackBright(`[${ident}] `) + `Marking "test-keys" check as ` + c.green(`successful`) + `.`);
          return true;
        } else {
          send(c.blackBright(`[${ident}] `) + `Marking "test-keys" check as ` + c.green(`failed`) + `.`);
          return false;
        }
      };

      return JavaString;
    });
  };

  const execSuCheck = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const JavaRuntime: Runtime = Java.use("java.lang.Runtime");
      const iOException: IOException = Java.use("java.io.IOException");

      JavaRuntime.exec.overload("java.lang.String").implementation = function (command: string) {
        if (command.endsWith("su")) {
          if (success) {
            send(c.blackBright(`[${ident}] `) + `Check for 'su' using command exec detected, allowing.`);
            return this.apply(this, arguments);
          } else {
            send(c.blackBright(`[${ident}] `) + `Check for 'su' using command exec detected, throwing IOException.`);
            throw iOException.$new("objection anti-root");
          }
        }

        // call the original method
        return this.exec.overload("java.lang.String").call(this, command);
      };

      return JavaRuntime;
    });
  };

  const fileExistsCheck = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const JavaFile: File = Java.use("java.io.File");
      JavaFile.exists.implementation = function () {
        const filename = this.getAbsolutePath();
        if (commonPaths.indexOf(filename) >= 0) {
          if (success) {
            send(
              c.blackBright(`[${ident}] `) +
              `File existence check for ${filename} detected, marking as ${c.green("true")}.`,
            );
            return true;
          } else {
            send(
              c.blackBright(`[${ident}] `) +
              `File existence check for ${filename} detected, marking as ${c.green("false")}.`,
            );
            return false;
          }
        }

        // call the original method
        return this.exists.call(this);
      };

      return JavaFile;
    });
  };

  const jailMonkeyBypass = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const JavaJailMonkeyModule = Java.use("com.gantix.JailMonkey.JailMonkeyModule");
      const JavaHashMap = Java.use("java.util.HashMap");
      const JavaFalseObject = Java.use("java.lang.Boolean").FALSE.value;
      JavaJailMonkeyModule.getConstants.implementation = function() {
        send(
          c.blackBright(`[${ident}] `) +
          `JailMonkeyModule.getConstants() called, returning false for all keys.`
        );
        const hm = JavaHashMap.$new();
        hm.put("isJailBroken", false_object);
        hm.put("hookDetected", false_object);
        hm.put("canMockLocation", false_object);
        hm.put("isOnExternalStorage", false_object);
        hm.put("AdbEnabled", false_object);
        return hm;
      };
      return JavaJailMonkeyModule;
    });
  };

  export const disable = (): void => {
    const job: IJob = {
      identifier: jobs.identifier(),
      implementations: [],
      type: "root-detection-disable",
    };

    job.implementations.push(testKeysCheck(false, job.identifier));
    job.implementations.push(execSuCheck(false, job.identifier));
    job.implementations.push(fileExistsCheck(false, job.identifier));
    job.implementations.push(jailMonkeyBypass(false, job.identifier));
    jobs.add(job);
  };

  export const enable = (): void => {
    const job: IJob = {
      identifier: jobs.identifier(),
      implementations: [],
      type: "root-detection-enable",
    };

    job.implementations.push(testKeysCheck(true, job.identifier));
    job.implementations.push(execSuCheck(true, job.identifier));
    job.implementations.push(fileExistsCheck(true, job.identifier));
    job.implementations.push(jailMonkeyBypass(true, job.identifier));
    jobs.add(job);
  };
}
