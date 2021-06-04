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

  const bypassRootBeer_isRooted = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");      
      RootBeer.isRooted.overload().implementation = function() {
        if (success) {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->isRooted() check detected, marking as ${c.green("true")}.`,
            );
            return true;
        } else {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->isRooted() check detected, marking as ${c.green("false")}.`,
            );
            return false;
        }
        // call the original method
        return this.isRooted.call(this);
      };
      return RootBeer;
    });
  }; 

  const bypassRootBeer_checkForBinary = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");  
      RootBeer.checkForBinary.overload('java.lang.String').implementation = function() {
        if (success) {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->checkForBinary() check detected, marking as ${c.green("true")}.`,
            );
            return true;
        } else {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->checkForBinary() check detected, marking as ${c.green("false")}.`,
            );
            return false;
        }
        // call the original method
        return this.checkForBinary.overload('java.lang.String').call(this);

      };
      return RootBeer;
    });
  };

  const bypassRootBeer_checkForDangerousProps = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
      RootBeer.checkForDangerousProps.overload().implementation = function() {
        if (success) {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->checkForDangerousProps() check detected, marking as ${c.green("true")}.`,
            );
            return true;
        } else {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->checkForDangerousProps() check detected, marking as ${c.green("false")}.`,
            );
            return false;
        }
        // call the original method
        return this.checkForDangerousProps.call(this);
      };
      return RootBeer;
    });
  };

  const bypassRootBeer_detectRootCloakingApps = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
      RootBeer.detectRootCloakingApps.overload().implementation = function() {
        if (success) {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->detectRootCloakingApps() check detected, marking as ${c.green("true")}.`,
            );
            return true;
        } else {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->detectRootCloakingApps() check detected, marking as ${c.green("false")}.`,
            );
            return false;
        }
        // call the original method
        return this.detectRootCloakingApps.call(this);
      };
      return RootBeer;
    });
  };

  const bypassRootBeer_checkSuExists = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
      RootBeer.checkSuExists.overload().implementation = function() {
        if (success) {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->checkSuExists() check detected, marking as ${c.green("true")}.`,
            );
            return true;
        } else {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->checkSuExists() check detected, marking as ${c.green("false")}.`,
            );
            return false;
        }
        // call the original method
        return this.checkSuExists.call(this);
      };
      return RootBeer;
    });
  };
  
  const bypassRootBeer_detectTestKeys = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
      RootBeer.detectTestKeys.overload().implementation = function() {
        if (success) {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->detectTestKeys() check detected, marking as ${c.green("true")}.`,
            );
            return true;
        } else {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->detectTestKeys() check detected, marking as ${c.green("false")}.`,
            );
            return false;
        }
        // call the original method
        return this.detectTestKeys.call(this);
      };
      return RootBeer;
    });
  }; 

  const bypassRootBeerNative = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const RootBeerNative = Java.use("com.scottyab.rootbeer.RootBeerNative");
      RootBeerNative.checkForRoot.overload('[Ljava.lang.Object;').implementation = function() {
        if (success) {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeerNative->checkForRoot() check detected, marking as ${c.green("1")}.`,
            );
            return 1;
        } else {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeerNative->checkForRoot() check detected, marking as ${c.green("0")}.`,
            );
            return 0;
        }
        // call the original method
        return this.checkForRoot.overload('[Ljava.lang.Object;').call(this);
      };
      return RootBeerNative;
    });
  }; 

  const bypassRootBeerObfuscatedA = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      /*
      package com.scottyab.rootbeer;
      public class d {
        public boolean s() {
          return o() || k() || b("su") || b("busybox") || d() || g() || q() || j() || h() || e();
        }
      }
      */
      const RootBeer = Java.use("com.scottyab.rootbeer.d");      
      // obfuscated isRootedWithBusyBoxCheck
      RootBeer.s.overload().implementation = function() {
        if (success) {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->isRootedWithBusyBoxCheck() check detected, marking as ${c.green("true")}.`,
            );
            return true;
        } else {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->isRootedWithBusyBoxCheck() check detected, marking as ${c.green("false")}.`,
            );
            return false;
        }
        // call the original method
        return this.s.call(this);
      };
      return RootBeer;
    });
  };

  const bypassRootBeerObfuscatedB = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      const RootBeer = Java.use("com.scottyab.rootbeer.d");
      // obfuscated checkForBinary
      RootBeer.b.overload('java.lang.String').implementation = function() {
        if (success) {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->checkForBinary() check detected, marking as ${c.green("true")}.`,
            );
            return true;
        } else {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->checkForBinary() check detected, marking as ${c.green("false")}.`,
            );
            return false;
        }
        // call the original method
        return this.b.overload('java.lang.String').call(this);
      };
      return RootBeer;
    });
  };

  const bypassRootBeerObfuscatedC = (success: boolean, ident: string): any => {
    return wrapJavaPerform(() => {
      /*
      package com.scottyab.rootbeer;
      public class d {
        public boolean t() {
          return o() || k() || b("su") || d() || g() || q() || j() || h() || e();
        }
      }
      */
      const RootBeer = Java.use("com.scottyab.rootbeer.d");
      // obfuscated isRooted
      RootBeer.t.overload().implementation = function() {
        if (success) {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->isRooted() check detected, marking as ${c.green("true")}.`,
            );
            return true;
        } else {
            send(
              c.blackBright(`[${ident}] `) +
              `RootBeer->isRooted() check detected, marking as ${c.green("false")}.`,
            );
            return false;
        }
        // call the original method
        return this.t.call(this);
      };
      return RootBeer;
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
    
    // RootBeer functions
    job.implementations.push(bypassRootBeer_isRooted(false, job.identifier));
    job.implementations.push(bypassRootBeer_checkForBinary(false, job.identifier));
    job.implementations.push(bypassRootBeer_checkForDangerousProps(false, job.identifier));
    job.implementations.push(bypassRootBeer_detectRootCloakingApps(false, job.identifier));
    job.implementations.push(bypassRootBeer_checkSuExists(false, job.identifier));
    job.implementations.push(bypassRootBeer_detectTestKeys(false, job.identifier));
    job.implementations.push(bypassRootBeerNative(false, job.identifier));
    job.implementations.push(bypassRootBeerObfuscatedA(false, job.identifier));
    job.implementations.push(bypassRootBeerObfuscatedB(false, job.identifier));
    job.implementations.push(bypassRootBeerObfuscatedC(false, job.identifier));
    
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
    
    // RootBeer functions
    job.implementations.push(bypassRootBeer_isRooted(true, job.identifier));
    job.implementations.push(bypassRootBeer_checkForBinary(true, job.identifier));
    job.implementations.push(bypassRootBeer_checkForDangerousProps(true, job.identifier));
    job.implementations.push(bypassRootBeer_detectRootCloakingApps(true, job.identifier));
    job.implementations.push(bypassRootBeer_checkSuExists(true, job.identifier));
    job.implementations.push(bypassRootBeer_detectTestKeys(true, job.identifier));
    job.implementations.push(bypassRootBeerNative(true, job.identifier));
    job.implementations.push(bypassRootBeerObfuscatedA(true, job.identifier));
    job.implementations.push(bypassRootBeerObfuscatedB(true, job.identifier));
    job.implementations.push(bypassRootBeerObfuscatedC(true, job.identifier));

    jobs.add(job);
  };
}
