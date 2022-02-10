import { colors as c } from "../lib/color";
import { IJob } from "../lib/interfaces";
import { jobs } from "../lib/jobs";
import { wrapJavaPerform } from "./lib/libjava";
import {
  File,
  IOException,
  JavaString,
  Runtime
} from "./lib/types";

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
        }

        send(c.blackBright(`[${ident}] `) + `Marking "test-keys" check as ` + c.green(`failed`) + `.`);
        return false;
      };
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
          }

          send(c.blackBright(`[${ident}] `) + `Check for 'su' using command exec detected, throwing IOException.`);
          throw iOException.$new("objection anti-root");
        }

        // call the original method
        return this.exec.overload("java.lang.String").call(this, command);
      };
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
    });
  };

  // RootBeer: https://github.com/scottyab/rootbeer

  const rootBeerIsRooted = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
      RootBeer.isRooted.overload().implementation = function () {
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
    });
  };

  const rootBeerCheckForBinary = (success: boolean, ident: string): any => {
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
    });
  };

  const rootBeerCheckForDangerousProps = (success: boolean, ident: string): any => {
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
    });
  };

  const rootBeerDetectRootCloakingApps = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
      RootBeer.detectRootCloakingApps.overload().implementation = function () {
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
    });
  };

  const rootBeerCheckSuExists = (success: boolean, ident: string): any => {
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
    });
  };

  const rootBeerDetectTestKeys = (success: boolean, ident: string): any => {
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
    });
  };

  const rootBeerCheckSeLinux = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
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
    });
  };

  const rootBeerNative = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const RootBeerNative = Java.use("com.scottyab.rootbeer.RootBeerNative");
      RootBeerNative.checkForRoot.overload('[Ljava.lang.Object;').implementation = function () {
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
    });
  };

  // ref: https://www.ayrx.me/gantix-jailmonkey-root-detection-bypass/
  const jailMonkeyBypass = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const JavaJailMonkeyModule = Java.use("com.gantix.JailMonkey.JailMonkeyModule");
      const JavaHashMap = Java.use("java.util.HashMap");
      const JavaFalseObject = Java.use("java.lang.Boolean").FALSE.value;

      JavaJailMonkeyModule.getConstants.implementation = function () {
        send(
          c.blackBright(`[${ident}] `) +
          `JailMonkeyModule.getConstants() called, returning false for all keys.`
        );

        const hm = JavaHashMap.$new();
        hm.put("isJailBroken", JavaFalseObject);
        hm.put("hookDetected", JavaFalseObject);
        hm.put("canMockLocation", JavaFalseObject);
        hm.put("isOnExternalStorage", JavaFalseObject);
        hm.put("AdbEnabled", JavaFalseObject);

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

    // RootBeer functions
    job.implementations.push(rootBeerIsRooted(false, job.identifier));
    job.implementations.push(rootBeerCheckForBinary(false, job.identifier));
    job.implementations.push(rootBeerCheckForDangerousProps(false, job.identifier));
    job.implementations.push(rootBeerDetectRootCloakingApps(false, job.identifier));
    job.implementations.push(rootBeerCheckSuExists(false, job.identifier));
    job.implementations.push(rootBeerDetectTestKeys(false, job.identifier));
    job.implementations.push(rootBeerNative(false, job.identifier));
    job.implementations.push(rootBeerCheckSeLinux(false, job.identifier));

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

    // RootBeer functions
    job.implementations.push(rootBeerIsRooted(true, job.identifier));
    job.implementations.push(rootBeerCheckForBinary(true, job.identifier));
    job.implementations.push(rootBeerCheckForDangerousProps(true, job.identifier));
    job.implementations.push(rootBeerDetectRootCloakingApps(true, job.identifier));
    job.implementations.push(rootBeerCheckSuExists(true, job.identifier));
    job.implementations.push(rootBeerDetectTestKeys(true, job.identifier));
    job.implementations.push(rootBeerNative(true, job.identifier));
    job.implementations.push(rootBeerCheckSeLinux(false, job.identifier));

    jobs.add(job);
  };
};
