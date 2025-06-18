import { colors as c } from "../lib/color.js";
import * as jobs from "../lib/jobs.js";
import {
  wrapJavaPerform,
  Java
} from "./lib/libjava.js";
import {
  File,
  IOException,
  JavaString,
  Runtime
} from "./lib/types.js";

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

const testKeysCheck = (success: boolean, ident: number): any => {
  return wrapJavaPerform(() => {
    const JavaString: JavaString = Java.use("java.lang.String");

    JavaString.contains.implementation = function (name) {
      if (name !== "test-keys") {
        return this.contains.call(this, name);
      }

      if (success) {
        send(c.blackBright(`[${ident}] `) + `Marking "test-keys" check as ` + c.green(`successful`) + `.`);
        return true;
      }

      send(c.blackBright(`[${ident}] `) + `Marking "test-keys" check as ` + c.green(`failed`) + `.`);
      return false;
    };

    return JavaString.contains;
  });
};

const execSuCheck = (success: boolean, ident: number): any => {
  return wrapJavaPerform(() => {
    const JavaRuntime: Runtime = Java.use("java.lang.Runtime");
    const iOException: IOException = Java.use("java.io.IOException");
    const JavaRuntime_exec = JavaRuntime.exec.overload("java.lang.String");

    JavaRuntime_exec.implementation = function (command: string) {
      if (command.endsWith("su")) {
        if (success) {
          send(c.blackBright(`[${ident}] `) + `Check for 'su' using command exec detected, allowing.`);
          return this.apply(this, arguments);
        }

        send(c.blackBright(`[${ident}] `) + `Check for 'su' using command exec detected, throwing IOException.`);
        throw iOException.$new("objection anti-root");
      }

      // call the original method
      return this.exec.overload("java.lang.String").call(this, command);
    };

    return JavaRuntime_exec;
  });
};

const fileExistsCheck = (success: boolean, ident: number): any => {
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
        }

        send(
          c.blackBright(`[${ident}] `) +
          `File existence check for ${filename} detected, marking as ${c.green("false")}.`,
        );
        return false;
      }

      // call the original method
      return this.exists.call(this);
    };

    return JavaFile.exists;
  });
};

// RootBeer: https://github.com/scottyab/rootbeer

const rootBeerIsRooted = (success: boolean, ident: number): any => {
  return wrapJavaPerform(() => {
    const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    const RootBeer_isRooted = RootBeer.isRooted.overload();

    RootBeer_isRooted.implementation = function () {
      if (success) {
        send(
          c.blackBright(`[${ident}] `) +
          `RootBeer->isRooted() check detected, marking as ${c.green("true")}.`,
        );
        return true;
      }

      send(
        c.blackBright(`[${ident}] `) +
        `RootBeer->isRooted() check detected, marking as ${c.green("false")}.`,
      );
      return false;
    };

    return RootBeer_isRooted;
  });
};

const rootBeerCheckForBinary = (success: boolean, ident: number): any => {
  return wrapJavaPerform(() => {
    const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.checkForBinary.overload('java.lang.String').implementation = function () {
      if (success) {
        send(
          c.blackBright(`[${ident}] `) +
          `RootBeer->checkForBinary() check detected, marking as ${c.green("true")}.`,
        );
        return true;
      }

      send(
        c.blackBright(`[${ident}] `) +
        `RootBeer->checkForBinary() check detected, marking as ${c.green("false")}.`,
      );
      return false;
    };

    return RootBeer.checkForBinary;
  });
};

const rootBeerCheckForDangerousProps = (success: boolean, ident: number): any => {
  return wrapJavaPerform(() => {
    const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.checkForDangerousProps.overload().implementation = function () {
      if (success) {
        send(
          c.blackBright(`[${ident}] `) +
          `RootBeer->checkForDangerousProps() check detected, marking as ${c.green("true")}.`,
        );
        return true;
      }

      send(
        c.blackBright(`[${ident}] `) +
        `RootBeer->checkForDangerousProps() check detected, marking as ${c.green("false")}.`,
      );
      return false;
    };

    return RootBeer.checkForDangerousProps;
  });
};

const rootBeerDetectRootCloakingApps = (success: boolean, ident: number): any => {
  return wrapJavaPerform(() => {
    const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    const RootBeer_detectRootCloakingApps = RootBeer.detectRootCloakingApps.overload();

    RootBeer_detectRootCloakingApps.implementation = function () {
      if (success) {
        send(
          c.blackBright(`[${ident}] `) +
          `RootBeer->detectRootCloakingApps() check detected, marking as ${c.green("true")}.`,
        );
        return true;
      }

      send(
        c.blackBright(`[${ident}] `) +
        `RootBeer->detectRootCloakingApps() check detected, marking as ${c.green("false")}.`,
      );
      return false;
    };

    return RootBeer_detectRootCloakingApps;
  });
};

const rootBeerCheckSuExists = (success: boolean, ident: number): any => {
  return wrapJavaPerform(() => {
    const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.checkSuExists.overload().implementation = function () {
      if (success) {
        send(
          c.blackBright(`[${ident}] `) +
          `RootBeer->checkSuExists() check detected, marking as ${c.green("true")}.`,
        );
        return true;
      }

      send(
        c.blackBright(`[${ident}] `) +
        `RootBeer->checkSuExists() check detected, marking as ${c.green("false")}.`,
      );
      return false;
    };

    return RootBeer.checkSuExists;
  });
};

const rootBeerDetectTestKeys = (success: boolean, ident: number): any => {
  return wrapJavaPerform(() => {
    const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.detectTestKeys.overload().implementation = function () {
      if (success) {
        send(
          c.blackBright(`[${ident}] `) +
          `RootBeer->detectTestKeys() check detected, marking as ${c.green("true")}.`,
        );
        return true;
      }

      send(
        c.blackBright(`[${ident}] `) +
        `RootBeer->detectTestKeys() check detected, marking as ${c.green("false")}.`,
      );
      return false;
    };

    return RootBeer.detectTestKeys;
  });
};

const rootBeerCheckSeLinux = (success: boolean, ident: number): any => {
  return wrapJavaPerform(() => {
    try {
      const Util = Java.use("com.scottyab.rootbeer.util");
      Util.isSelinuxFlagInEnabled.overload().implementation = function () {
        if (success) {
          send(
            c.blackBright(`[${ident}]`) +
            `Rootbeer.util->isSelinuxFlagInEnabled() check detected, marking as ${c.green("true")}`,
          );
          return true;
        }
  
        send(
          c.blackBright(`[${ident}] `) +
          `Rootbeer.util->isSelinuxFlagInEnabled() check detected, marking as ${c.green("false")}`,
        );
        return false;
      };
  
      return Util.isSelinuxFlagInEnabled;
    } catch (err) {
      if ((err as Error).message.indexOf("java.lang.ClassNotFoundException") === 0) {
        return null;
      };
      throw err;
    }
  });
};

const rootBeerNative = (success: boolean, ident: number): any => {
  return wrapJavaPerform(() => {
    const RootBeerNative = Java.use("com.scottyab.rootbeer.RootBeerNative");
    const RootBeerNative_checkForRoot = RootBeerNative.checkForRoot.overload('[Ljava.lang.Object;');
    RootBeerNative_checkForRoot.implementation = function () {
      if (success) {
        send(
          c.blackBright(`[${ident}] `) +
          `RootBeerNative->checkForRoot() check detected, marking as ${c.green("1")}.`,
        );
        return 1;
      }

      send(
        c.blackBright(`[${ident}] `) +
        `RootBeerNative->checkForRoot() check detected, marking as ${c.green("0")}.`,
      );
      return 0;
    };

    return RootBeerNative_checkForRoot;
  });
};

// ref: https://www.ayrx.me/gantix-jailmonkey-root-detection-bypass/
const jailMonkeyBypass = (success: boolean, ident: number): Promise<any> => {
  return wrapJavaPerform(() => {
    try {
      const JavaJailMonkeyModule = Java.use("com.gantix.JailMonkey.JailMonkeyModule");
      const JavaHashMap = Java.use("java.util.HashMap");
      const JavaBoolean = Java.use("java.lang.Boolean")
      const JavaFalseObject = JavaBoolean.FALSE.value;
      const JavaTrueObject = JavaBoolean.TRUE.value;

      JavaJailMonkeyModule.getConstants.implementation = function () {
        if (success) {
          send(
            c.blackBright(`[${ident}] `) +
            `RootBeer->checkForDangerousProps() check detected, marking as ${c.green("true")} for all keys.`,
          );
          const hm = JavaHashMap.$new();
          hm.put("isJailBroken", JavaTrueObject);
          hm.put("hookDetected", JavaTrueObject);
          hm.put("canMockLocation", JavaTrueObject);
          hm.put("isOnExternalStorage", JavaTrueObject);
          hm.put("AdbEnabled", JavaTrueObject);
          
          return hm;
        }
        send(
          c.blackBright(`[${ident}] `) +
          `JailMonkeyModule.getConstants() called, returning ${c.green("false")} for all keys.`
        );

        const hm = JavaHashMap.$new();
        hm.put("isJailBroken", JavaFalseObject);
        hm.put("hookDetected", JavaFalseObject);
        hm.put("canMockLocation", JavaFalseObject);
        hm.put("isOnExternalStorage", JavaFalseObject);
        hm.put("AdbEnabled", JavaFalseObject);

        return hm;
      };

      return JavaJailMonkeyModule.getConstants;
    } catch (err) {
      if ((err as Error).message.indexOf("java.lang.ClassNotFoundException") === 0) {
        return null;
      };
      throw err;
    }
  });
};

export const disable = async (): Promise<void> => {
  const job: jobs.Job = new jobs.Job(jobs.identifier(), 'root-detection-disable');

  job.addImplementation(await testKeysCheck(false, job.identifier));
  job.addImplementation(await execSuCheck(false, job.identifier));
  job.addImplementation(await fileExistsCheck(false, job.identifier));
  job.addImplementation(await jailMonkeyBypass(false, job.identifier));
  // RootBeer functions
  job.addImplementation(await rootBeerIsRooted(false, job.identifier));
  job.addImplementation(await rootBeerCheckForBinary(false, job.identifier));
  job.addImplementation(await rootBeerCheckForDangerousProps(false, job.identifier));
  job.addImplementation(await rootBeerDetectRootCloakingApps(false, job.identifier));
  job.addImplementation(await rootBeerCheckSuExists(false, job.identifier));
  job.addImplementation(await rootBeerDetectTestKeys(false, job.identifier));
  job.addImplementation(await rootBeerNative(false, job.identifier));
  job.addImplementation(await rootBeerCheckSeLinux(false, job.identifier));

  jobs.add(job);
};

export const enable = async (): Promise<void> => {
  const job: jobs.Job = new jobs.Job(jobs.identifier(), "root-detection-enable");

  job.addImplementation(await testKeysCheck(true, job.identifier));
  job.addImplementation(await execSuCheck(true, job.identifier));
  job.addImplementation(await fileExistsCheck(true, job.identifier));
  job.addImplementation(await jailMonkeyBypass(true, job.identifier));

  // RootBeer functions
  job.addImplementation(await rootBeerIsRooted(true, job.identifier));
  job.addImplementation(await rootBeerCheckForBinary(true, job.identifier));
  job.addImplementation(await rootBeerCheckForDangerousProps(true, job.identifier));
  job.addImplementation(await rootBeerDetectRootCloakingApps(true, job.identifier));
  job.addImplementation(await rootBeerCheckSuExists(true, job.identifier));
  job.addImplementation(await rootBeerDetectTestKeys(true, job.identifier));
  job.addImplementation(await rootBeerNative(true, job.identifier));
  job.addImplementation(await rootBeerCheckSeLinux(false, job.identifier));

  jobs.add(job);
};
