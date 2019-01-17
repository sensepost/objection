import { colors as c } from "../lib/color";
import { IJob } from "../lib/interfaces";
import { jobs } from "../lib/jobs";
import { getApplicationContext, wrapJavaPerform } from "./lib/libjava";
import { JavaClass } from "./lib/types";

export namespace hooking {

  export const getClasses = (): Promise<string[]> => {
    return wrapJavaPerform(() => {
      return Java.enumerateLoadedClassesSync();
    });
  };

  export const getClassMethods = (className: string): Promise<string[]> => {
    return wrapJavaPerform(() => {

      const clazz = Java.use(className);

      return clazz.class.getDeclaredMethods().map((method) => {
        return method.toGenericString();
      });
    });
  };

  export const watchClass = (clazz: string): Promise<void> => {
    return wrapJavaPerform(() => {
      const clazzInstance: JavaClass = Java.use(clazz);

      const uniqueMethods: string[] = clazzInstance.class.getDeclaredMethods().map((method) => {
        // perform a cleanup of the method. An example after toGenericString() would be:
        // public void android.widget.ScrollView.draw(android.graphics.Canvas) throws Exception
        let m = method.toGenericString();

        // remove any "Throws" the method may have
        if (m.indexOf(" throws ") !== -1) { m = m.substring(0, m.indexOf(" throws ")); }

        // remove scope and return type declarations (aka: first two words)
        // remove the class name
        // remove the signature and return
        m = m.slice(m.lastIndexOf(" "));
        m = m.replace(` ${clazz}.`, "");

        return m.split("(")[0];

      }).filter((value, index, self) => {
        return self.indexOf(value) === index;
      });

      // start a new job container
      const job: IJob = {
        identifier: jobs.identifier(),
        implementations: [],
        type: `watch-class for: ${clazz}`,
      };

      uniqueMethods.forEach((method) => {
        clazzInstance[method].overloads.forEach((m: any) => {

          // get the argument types for this overload
          const calleeArgTypes: string[] = m.argumentTypes.map((arg) => arg.className);
          send(`Hooking ${c.green(clazz)}.${c.greenBright(method)}(${c.red(calleeArgTypes.join(", "))})`);

          // replace the implementation of this method
          // tslint:disable-next-line:only-arrow-functions
          m.implementation = function() {
            send(
              c.blackBright(`[${job.identifier}] `) +
              `Called ${c.green(clazz)}.${c.greenBright(m.methodName)}(${c.red(calleeArgTypes.join(", "))})`,
            );

            // actually run the intended method
            return m.apply(this, arguments);
          };

          // record this implementation override for the job
          job.implementations.push(m);
        });
      });

      // record the job
      jobs.add(job);
    });
  };

  export const watchMethod = (fqClazz: string, dargs: boolean, dbt: boolean, dret: boolean): Promise<void> => {
    // split the fully qualified class name, assuming the last . denotes the method
    const methodSeperatorIndex: number = fqClazz.lastIndexOf(".");
    const clazz: string = fqClazz.substring(0, methodSeperatorIndex);
    const method: string = fqClazz.substring(methodSeperatorIndex + 1); // Increment by 1 to exclude the leading period

    send(`Attemtping to watch class ${c.green(clazz)} and method ${c.green(method)}.`);

    return wrapJavaPerform(() => {
      const Throwable = Java.use("java.lang.Throwable");
      const targetClass: JavaClass = Java.use(clazz);

      // Ensure that the method exists on the class
      if (targetClass[method] === undefined) {
        send(`${c.red("Error:")} Unable to find method ${c.redBright(method)} in class ${c.green(clazz)}`);
        return;
      }

      // start a new job container
      const job: IJob = {
        identifier: jobs.identifier(),
        implementations: [],
        type: `watch-method for: ${fqClazz}`,
      };

      targetClass[method].overloads.forEach((m: any) => {

        // get the argument types for this overload
        const calleeArgTypes: string[] = m.argumentTypes.map((arg) => arg.className);
        send(`Hooking ${c.green(clazz)}.${c.greenBright(method)}(${c.red(calleeArgTypes.join(", "))})`);

        // replace the implementation of this method
        // tslint:disable-next-line:only-arrow-functions
        m.implementation = function() {
          send(
            c.blackBright(`[${job.identifier}] `) +
            `Called ${c.green(clazz)}.${c.greenBright(m.methodName)}(${c.red(calleeArgTypes.join(", "))})`,
          );

          // dump a backtrace
          if (dbt) {
            send(
              c.blackBright(`[${job.identifier}] `) + "Backtrace:\n\t" +
              Throwable.$new().getStackTrace().map((traceElement) => traceElement.toString() + "\n\t").join(""),
            );
          }

          // dump arguments
          if (dargs && calleeArgTypes.length > 0) {
            const argValues: string[] = [];
            for (const h of arguments) {
              argValues.push((h || "(none)").toString());
            }

            send(
              c.blackBright(`[${job.identifier}] `) +
              `Arguments ${c.green(clazz)}.${c.greenBright(m.methodName)}(${c.red(argValues.join(", "))})`,
            );
          }

          // actually run the intended method
          const retVal: any = m.apply(this, arguments);

          // dump the return value
          if (dret) {
            const retValStr: string = (retVal || "(none)").toString();
            send(c.blackBright(`[${job.identifier}] `) + `Return Value: ${c.red(retValStr)}`);
          }

          // also return the captured return value
          return retVal;
        };

        // record this implementation override for the job
        job.implementations.push(m);
      });

      // register the job
      jobs.add(job);
    });
  };

  export const getActivities = (): Promise<string[]> => {
    return wrapJavaPerform(() => {

      const PackageManager = Java.use("android.content.pm.PackageManager");
      const GET_ACTIVITIES = PackageManager.GET_ACTIVITIES.value;
      const context = getApplicationContext();

      return Array.prototype.concat(context.getPackageManager()
        .getPackageInfo(context.getPackageName(), GET_ACTIVITIES).activities.value.map((activityInfo) => {
          return activityInfo.name.value;
        }),
      );
    });
  };
}
