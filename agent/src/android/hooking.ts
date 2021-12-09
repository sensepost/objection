import { rejects } from "assert";
import { colors as c } from "../lib/color";
import { IJob } from "../lib/interfaces";
import { jobs } from "../lib/jobs";
import { ICurrentActivityFragment } from "./lib/interfaces";
import {
  getApplicationContext,
  R,
  wrapJavaPerform
} from "./lib/libjava";
import {
  Activity,
  ActivityClientRecord,
  ActivityThread,
  ArrayMap,
  JavaClass,
  PackageManager,
  Throwable,
} from "./lib/types";

export namespace hooking {

  import EnumerateMethodsMatchGroup = Java.EnumerateMethodsMatchGroup;
  import cast = Java.cast;
  import EnumerateMethodsMatchClass = Java.EnumerateMethodsMatchClass;
  const splitClassMethod = (fqClazz: string): string[] => {
    // split a fully qualified class name, assuming the last period denotes the method
    const methodSeperatorIndex: number = fqClazz.lastIndexOf(".");

    const clazz: string = fqClazz.substring(0, methodSeperatorIndex);
    const method: string = fqClazz.substring(methodSeperatorIndex + 1); // Increment by 1 to exclude the leading period

    return [clazz, method];
  };

  export const getClasses = (): Promise<string[]> => {
    return wrapJavaPerform(() => {
      return Java.enumerateLoadedClassesSync();
    });
  };

  export const getClassLoaders = (): Promise<string[]> => {
    return wrapJavaPerform(() => {
      const loaders: string[] = [];
      Java.enumerateClassLoaders({
        onMatch: function (l) {
          if (l == null) {
            return;
          }
          loaders.push(l.toString());
        },
        onComplete() { }
      });

      return loaders;
    });
  };

  enum PatternType {
    Regex = 'regex',
    Klass = 'klass',
  }
  const getPatternType = (pattern: string): PatternType => {
    if (pattern.indexOf('!') !== -1) {
      return PatternType.Regex
    } else {
      return PatternType.Klass
    }
  }
  export const lazyWatchForPattern = (query: string): void => {
    let found = false

    // Check if the pattern is found before starting an interval
    enumerate(query).then(matches => {
      if (matches.length > 0) {
        found = true
        send(`${c.green("Notify:")} Pattern ${c.green(query)} was matched`)
      }
    })

    if (found) {
      return
    }

    const interval = setInterval(() => {
      enumerate(query).then(matches => {
        // Only notify if we haven't before
        if (found == false && matches.length > 0) {
          send(`${c.green("Notify:")} Pattern ${c.green(query)} was matched`)
          clearInterval(interval)
        }
      })
    }, 1000 * 5);

  }
  export const enumerate = (query: string): Promise<EnumerateMethodsMatchGroup[]> => {
    // If the query is just a classname, strongarm it into a pattern.
    if (getPatternType(query) === PatternType.Klass) {
      query = `${query}!*`
    }
    return wrapJavaPerform(() => {
      return Java.enumerateMethods(query);
    }
    );
  };

  export const getClassMethods = (className: string): Promise<string[]> => {
    return wrapJavaPerform(() => {

      const clazz: JavaClass = Java.use(className);
      return clazz.class.getDeclaredMethods().map((method) => {
        return method.toGenericString();
      });
    });
  };
  // This function takes in a method such as package.class.perform()
  // and extracts only the method name, ie "perform"
  const genericMethodNameToMethodOnly = (fullMethodName: string): string => {
    // Reduces [package, class, perform()] to "perform()"
    const method = fullMethodName.split('.').filter((part: string) => part.includes('('))[0]
    // Now extract everything before the first '('
    return method.substring(0, method.indexOf('('))
  }
  // This method assumes that it's being called from inside wrapJavaPerform
  export const getClassHandle = (className: string): JavaClass | null => {
    let clazz: JavaClass = null
    const loaders = Java.enumerateClassLoadersSync()
    let found = false
    // Try to get a handle using each of the class loaders
    for (let i = 0; i < loaders.length; i++) {
      const loader = loaders[i]
      const factory = Java.ClassFactory.get(loader)
      try {
        clazz = factory.use(className)
        found = true
        break
      } catch { }
    }
    if (found) {
      return clazz
    } else {
      return null
    }
  }
  // This method assumes that it's being called from inside wrapJavaPerform
  // It behaves the same as the above, except only uses the specified class
  // loader
  export const getClassHandleWithLoaderClassName = (className: string, loaderClassName: any): JavaClass | null => {
    let clazz: JavaClass = null
    const loaders = Java.enumerateClassLoadersSync()
      .filter(loader => loaderClassName === loader.$className)

    if (loaders.length == 0) {
      return null
    } else {
      let found = false
      // Try to get a handle using each of the class loaders
      // This is still required because some loaders may have the
      // same name, so distinguishing between them using this is
      // incorrect. I'm sure there is a way of finding the correct
      // one efficiently.
      for (let i = 0; i < loaders.length; i++) {
        const loader = loaders[i]
        const factory = Java.ClassFactory.get(loader)
        try {
          clazz = factory.use(className)
          found = true
          break
        } catch { }
      }
      if (found) {
        return clazz
      } else {
        return null
      }
    }
  }
  export const getClassMethodsOverloads = (className: string, methodsAllowList: string[] = [], loader?: string): Promise<JSON> => {
    return wrapJavaPerform(() => {
      const result: any = {} // TODO(cduplooy): Properly type this.
      const clazz = loader !== null ? getClassHandleWithLoaderClassName(className, loader) : getClassHandle(className)

      if (clazz === null) {
        throw new Error("Could not find class!");
      }

      // TODO(cduplooy): The below line can fail with Error: java.lang.NoClassDefFoundError: Failed resolution of: Landroidx/datastore/core/DataStore;
      // This seems to involve custom class loaders...
      const methods = clazz.class.getDeclaredMethods()
        .map(method => genericMethodNameToMethodOnly(method.toGenericString()))
      methods.forEach(methodName => {
        if (methodsAllowList.length === 0 || (methodsAllowList.length > 0 && methodsAllowList.includes(methodName))) {
          const overloads = clazz[methodName].overloads
          result[methodName] = {
            'argTypes': overloads.map(overload => overload.argumentTypes),
            'returnType': overloads.map(overload => overload.returnType),
            'methodName': overloads.map(overload => overload.methodName),
            'handle': overloads.map(overload => overload.handle),
            'holder': overloads.map(overload => overload.holder),
            'type': overloads.map(overload => overload.type),
          }
        }
      })

      // Finally append the constructor details
      if (clazz.class.getConstructors().length > 0) {
        if (methodsAllowList.length === 0 || (methodsAllowList.length > 0 && methodsAllowList.includes("$init"))) {
          const overloads = clazz['$init'].overloads
          result['$init'] = {
            'argTypes': overloads.map(overload => overload.argumentTypes),
            'returnType': overloads.map(overload => overload.returnType),
            'methodName': overloads.map(overload => overload.methodName),
            'handle': overloads.map(overload => overload.handle),
            'holder': overloads.map(overload => overload.holder),
            'type': overloads.map(overload => overload.type),
          }
        }
      }

      return result
    });
  };
  export const watch = (pattern: string, dargs: boolean, dbt: boolean, dret: boolean): Promise<void> => {
    const patternType = getPatternType(pattern)
    if (patternType === PatternType.Klass) {
      return watchClass(pattern, dargs, dbt, dret)
    } else if (patternType === PatternType.Regex) {
      return new Promise((resolve, reject) => {
        enumerate(pattern).then((matches: EnumerateMethodsMatchGroup[]) => {
          matches.forEach((match: EnumerateMethodsMatchGroup) => {
            match.classes.forEach((klass: EnumerateMethodsMatchClass) => {
              klass.methods.forEach(method => {
                // Only watch matched methods
                watchMethod(`${klass.name}.${method}`, null, dargs, dbt, dret)
              })
            })
          })
          resolve()
        }).catch((error) => {
          reject(error)
        })
      })
    } else {
      // TODO(cduplooy): Unknown pattern type? log a message to inform the user?
    }
  }
  export const watchClass = (clazz: string, dargs: boolean = false, dbt: boolean = false, dret: boolean = false): Promise<void> => {
    return wrapJavaPerform(() => {
      const clazzInstance: JavaClass = Java.use(clazz);

      const uniqueMethods: string[] = clazzInstance.class.getDeclaredMethods().map((method) => {
        // perform a cleanup of the method. An example after toGenericString() would be:
        // public void android.widget.ScrollView.draw(android.graphics.Canvas) throws Exception
        // public final rx.c.b<java.lang.Throwable> com.apple.android.music.icloud.a.a(rx.c.b<java.lang.Throwable>)
        let m: string = method.toGenericString();

        // Remove generics from the method
        while (m.includes("<")) { m = m.replace(/<.*?>/g, ""); }

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
        // get the argument types for this overload
        send(`Watching ${c.green(clazz)}.${c.greenBright(method)}()`);
        const fqClazz = `${clazz}.${method}`;
        // TODO(cduplooy): Add the filter args, also jobs per invocation of parent command
        watchMethod(fqClazz, null, dargs, dbt, dret);
        // record this implementation override for the job
        job.implementations.push(fqClazz);
      });

      // record the job
      jobs.add(job);
    });
  };

  export const watchMethod = (
    fqClazz: string, filterOverload: string | null, dargs: boolean, dbt: boolean, dret: boolean,
  ): Promise<void> => {
    const [clazz, method] = splitClassMethod(fqClazz);
    send(`Attempting to watch class ${c.green(clazz)} and method ${c.green(method)}.`);

    if (filterOverload != null) {
      send(c.blackBright(`Will filter for method overload with arguments:`) +
        ` ${c.green(filterOverload)}`);
    }

    return wrapJavaPerform(() => {
      const throwable: Throwable = Java.use("java.lang.Throwable");
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

        // check if we need to filter on a specific overload
        if (filterOverload != null && calleeArgTypes.join(",") !== filterOverload) {
          return;
        }

        send(`Hooking ${c.green(clazz)}.${c.greenBright(method)}(${c.red(calleeArgTypes.join(", "))})`);

        // replace the implementation of this method
        // tslint:disable-next-line:only-arrow-functions
        m.implementation = function () {
          send(
            c.blackBright(`[${job.identifier}] `) +
            `Called ${c.green(clazz)}.${c.greenBright(m.methodName)}(${c.red(calleeArgTypes.join(", "))})`,
          );

          // dump a backtrace
          if (dbt) {
            send(
              c.blackBright(`[${job.identifier}] `) + "Backtrace:\n\t" +
              throwable.$new().getStackTrace().map((traceElement) => traceElement.toString() + "\n\t").join(""),
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

  export const getCurrentActivity = (): Promise<ICurrentActivityFragment> => {
    return wrapJavaPerform(() => {
      const activityThread: ActivityThread = Java.use("android.app.ActivityThread");
      const activity: Activity = Java.use("android.app.Activity");
      const activityClientRecord: ActivityClientRecord = Java.use("android.app.ActivityThread$ActivityClientRecord");

      const currentActivityThread = activityThread.currentActivityThread();
      const activityRecords = currentActivityThread.mActivities.value.values().toArray();
      let currentActivity;

      for (const i of activityRecords) {
        const activityRecord = Java.cast(i, activityClientRecord);
        if (!activityRecord.paused.value) {
          currentActivity = Java.cast(Java.cast(activityRecord, activityClientRecord).activity.value, activity);
          break;
        }
      }

      if (currentActivity) {
        // Discover an active fragment
        const fm = currentActivity.getFragmentManager();
        const fragment = fm.findFragmentById(R("content_frame", "id"));

        return {
          activity: currentActivity.$className,
          fragment: fragment.$className,
        };
      }

      return {
        activity: null,
        fragment: null,
      };
    });
  };

  export const getActivities = (): Promise<string[]> => {
    return wrapJavaPerform(() => {

      const packageManager: PackageManager = Java.use("android.content.pm.PackageManager");
      const GET_ACTIVITIES = packageManager.GET_ACTIVITIES.value;
      const context = getApplicationContext();

      return Array.prototype.concat(context.getPackageManager()
        .getPackageInfo(context.getPackageName(), GET_ACTIVITIES).activities.value.map((activityInfo) => {
          return activityInfo.name.value;
        }),
      );
    });
  };

  export const getServices = (): Promise<string[]> => {
    return wrapJavaPerform(() => {
      const activityThread: ActivityThread = Java.use("android.app.ActivityThread");
      const arrayMap: ArrayMap = Java.use("android.util.ArrayMap");
      const packageManager: PackageManager = Java.use("android.content.pm.PackageManager");

      const GET_SERVICES = packageManager.GET_SERVICES.value;

      const currentApplication = activityThread.currentApplication();
      // not using the helper as we need other variables too
      const context = currentApplication.getApplicationContext();

      let services = [];

      currentApplication.mLoadedApk.value.mServices.value.values().toArray().map((potentialServices) => {
        Java.cast(potentialServices, arrayMap).keySet().toArray().map((service) => {
          services.push(service.$className);
        });
      });

      services = services.concat(context.getPackageManager()
        .getPackageInfo(context.getPackageName(), GET_SERVICES).services.value.map((activityInfo) => {
          return activityInfo.name.value;
        }),
      );

      return services;
    });
  };

  export const getBroadcastReceivers = (): Promise<string[]> => {
    return wrapJavaPerform(() => {
      const activityThread: ActivityThread = Java.use("android.app.ActivityThread");
      const arrayMap: ArrayMap = Java.use("android.util.ArrayMap");
      const packageManager: PackageManager = Java.use("android.content.pm.PackageManager");

      const GET_RECEIVERS = packageManager.GET_RECEIVERS.value;

      const currentApplication = activityThread.currentApplication();
      // not using the helper as we need other variables too
      const context = currentApplication.getApplicationContext();

      let receivers = [];

      currentApplication.mLoadedApk.value.mReceivers.value.values().toArray().map((potentialReceivers) => {
        Java.cast(potentialReceivers, arrayMap).keySet().toArray().map((receiver) => {
          receivers.push(receiver.$className);
        });
      });

      receivers = receivers.concat(context.getPackageManager()
        .getPackageInfo(context.getPackageName(), GET_RECEIVERS).receivers.value.map((activityInfo) => {
          return activityInfo.name.value;
        }),
      );

      return receivers;
    });
  };

  export const setReturnValue = (fqClazz: string, filterOverload: string | null, newRet: boolean): Promise<void> => {
    const [clazz, method] = splitClassMethod(fqClazz);
    send(`Attempting to modify return value for class ${c.green(clazz)} and method ${c.green(method)}.`);

    if (filterOverload != null) {
      send(c.blackBright(`Will filter for method overload with arguments:`) +
        ` ${c.green(filterOverload)}`);
    }

    return wrapJavaPerform(() => {
      const job: IJob = {
        identifier: jobs.identifier(),
        implementations: [],
        type: `set-return for: ${fqClazz}`,
      };

      const targetClazz: JavaClass = Java.use(clazz);

      targetClazz[method].overloads.forEach((m: any) => {
        // get the argument types for this method
        const calleeArgTypes: string[] = m.argumentTypes.map((arg) => arg.className);

        // check if we need to filter on a specific overload
        if (filterOverload != null && calleeArgTypes.join(",") !== filterOverload) {
          return;
        }

        send(`Hooking ${c.green(clazz)}.${c.greenBright(method)}(${c.red(calleeArgTypes.join(", "))})`);

        // tslint:disable-next-line:only-arrow-functions
        m.implementation = function () {
          let retVal = m.apply(this, arguments);

          // Override retval if needed
          if (retVal !== newRet) {
            send(
              c.blackBright(`[${job.identifier}] `) + `Return value was not ${c.red(newRet.toString())}, ` +
              `setting to ${c.green(newRet.toString())}.`,
            );
            // update the return value
            retVal = newRet;
          }
          return retVal;
        };

        // record override
        job.implementations.push(m);
      });

      jobs.add(job);
    });
  };
}
