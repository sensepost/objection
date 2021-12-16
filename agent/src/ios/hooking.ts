import { colors as c } from "../lib/color";
import { IJob } from "../lib/interfaces";
import { jobs } from "../lib/jobs";

export namespace hooking {

  export const getClasses = () => {
    return ObjC.classes;
  };

  export const getClassMethods = (className: string, includeParents: boolean): string[] => {
    if (ObjC.classes[className] === undefined) {
      return [];
    }

    // Show all methods of the class
    if (includeParents) {
      return ObjC.classes[className].$methods;
    }

    return ObjC.classes[className].$ownMethods;
  };
  export const enumerate = (pattern: string, registerJob: boolean = true): ApiResolverMatch[] => {
    const resolver = new ApiResolver('objc')
    const job: IJob = {
      identifier: jobs.identifier(),
      invocations: [],
      type: `ios-enumerate for: ${pattern}`,
    };
    jobs.add(job)
    return resolver.enumerateMatches(pattern)
  };
  export const searchMethods = (partial: string): string[] => {
    const results: string[] = []; // the response 

    Object.keys(ObjC.classes).forEach((clazz: string) => {
      ObjC.classes[clazz].$ownMethods.forEach((method) => {

        if (method.toLowerCase().indexOf(partial) !== -1) {
          results.push(`[` + ObjC.classes[clazz].$className + ` ` + method + `]`);
        }
      });
    });

    return results;
  };
  export const watchClass = (clazz: string, job: IJob, dargs: boolean = false, dbt: boolean = false, dret: boolean = false, parents: boolean = false): void => {
    const target = ObjC.classes[clazz];

    if (!target) {
      send(`${c.red(`Error!`)} Unable to find class ${c.redBright(clazz)}!`);
      return;
    }

    // with parents as true, include methods from a parent class,
    // otherwise simply hook the target class' own  methods
    (parents ? target.$methods : target.$ownMethods).forEach((method) => {
      // filter and make sure we have a type and name. Looks like some methods can
      // have '' as name... am expecting something like "- isJailBroken"
      const fullMethodName = `${method[0]}[${clazz} ${method.substring(2)}]`
      watchMethod(fullMethodName, job, dargs, dbt, dret)
    });

  };
  export const search = (patternOrClass: string): ApiResolverMatch[] => {
    const isPattern = patternOrClass.includes('[')
    if (isPattern === false) {
      // Make a pattern
      return enumerate(`*[${patternOrClass} *]`)
    } else {
      return enumerate(patternOrClass)
    }
  }
  export const watch = (patternOrClass: string, dargs: boolean = false, dbt: boolean = false, dret: boolean = false, watchParents: boolean = false): void => {
    // Add the job
    const job: IJob = {
      identifier: jobs.identifier(),
      invocations: [],
      type: `ios-watch for: ${patternOrClass}`,
    };
    jobs.add(job)

    const isPattern = patternOrClass.includes('[')
    if (isPattern === true) {
      const matches = enumerate(patternOrClass, false)
      matches.forEach((match: ApiResolverMatch) => {
        watchMethod(match.name, job, dargs, dbt, dret)
      })
    } else {
      watchClass(patternOrClass, job, dargs, dbt, dret, watchParents)
    }
  }
  export const watchMethod = (selector: string, job: IJob, dargs: boolean, dbt: boolean, dret: boolean): void => {
    const resolver = new ApiResolver("objc");
    let matchedMethod = {
      address: undefined,
      name: undefined,
    };

    // handle the resolvers error it may throw if the selector format is off.
    try {
      // select the first match
      const ressolved = resolver.enumerateMatches(selector);
      if (ressolved.length <= 0) {
        send(`${c.red(`Error:`)} No matches for selector ${c.redBright(`${selector}`)}. ` +
          `Double check the name, or try "ios hooking list class_methods" first.`);
        return;
      }

      // not sure if this will ever be the case... but lets log it
      // anyways
      if (ressolved.length > 1) {
        send(`${c.yellow(`Warning:`)} More than one result for selector ${c.redBright(`${selector}`)}!`);
      }

      matchedMethod = ressolved[0];
    } catch (error) {
      send(
        `${c.red(`Error:`)} Unable to find address for selector ${c.redBright(`${selector}`)}! ` +
        `The error was:\n` + c.red((error as Error).message),
      );
      return;
    }

    // Attach to the discovered match
    // TODO: loop correctly when globbing
    send(`Found selector at ${c.green(matchedMethod.address.toString())} as ${c.green(matchedMethod.name)}`);

    const watchInvocation: InvocationListener = Interceptor.attach(matchedMethod.address, {
      // tslint:disable-next-line:object-literal-shorthand
      onEnter: function (args) {
        // how many arguments do we have in this selector?
        const argumentCount: number = (selector.match(/:/g) || []).length;
        const receiver = new ObjC.Object(args[0]);
        send(
          c.blackBright(`[${job.identifier}] `) +
          `Called: ${c.green(`${selector}`)} ${c.blue(`${argumentCount}`)} arguments` +
          `(Kind: ${c.cyan(receiver.$kind)}) (Super: ${c.cyan(receiver.$superClass.$className)})`,
        );

        // if we should include a backtrace to here, do that.
        if (dbt) {
          send(
            c.blackBright(`[${job.identifier}] `) +
            `${c.green(`${selector}`)} Backtrace:\n\t` +
            Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t"),
          );
        }

        if (dargs && argumentCount > 0) {
          const methodSplit = ObjC.selectorAsString(args[1]).split(":").filter((val) => val);
          const r = methodSplit.map((argName, position) => {
            // As this is an ObjectiveC method, the arguments are as follows:
            // 0. 'self'
            // 1. The selector (object.name:)
            // 2. The first arg
            //
            // For this reason do we shift it by 2 positions to get an 'instance' for
            // the argument value.
            const t = new ObjC.Object(args[position + 2]);
            return `${argName}: ${c.greenBright(`${t}`)}`;
          });

          send(c.blackBright(`[${job.identifier}] `) +
            `Argument dump: [${c.green(receiver.$className)} ${r.join(" ")}]`);
        }
      },
      onLeave: (retval) => {
        // do nothing if we are not expected to dump return values
        if (!dret) { return; }
        send(c.blackBright(`[${job.identifier}] `) + `Return Value: ${c.red(retval.toString())}`);
      },
    });
  };

  export const setMethodReturn = (selector: string, returnValue: boolean): void => {
    const TRUE = new NativePointer(0x1);
    const FALSE = new NativePointer(0x0);

    const resolver = new ApiResolver("objc");
    let matchedMethod = {
      address: undefined,
      name: undefined,
    };

    // handle the resolvers error it may throw if the selector format
    // is off.
    try {
      // select the first match
      matchedMethod = resolver.enumerateMatches(selector)[0];
    } catch (error) {
      send(
        `${c.red(`Error!`)} Unable to find address for selector ${c.redBright(`${selector}`)}! ` +
        `The error was:\n` + c.red((error as Error).message),
      );
      return;
    }

    // no match? then just leave.
    if (!matchedMethod.address) {
      send(`${c.red(`Error!`)} Unable to find address for selector ${c.redBright(`${selector}`)}!`);
      return;
    }

    // Start a new Job
    const job: IJob = {
      identifier: jobs.identifier(),
      invocations: [],
      type: `set-method-return for: ${selector}`,
    };

    // Attach to the discovered match
    // TODO: loop correctly when globbing
    send(`Found selector at ${c.green(matchedMethod.address.toString())} as ${c.green(matchedMethod.name)}`);
    const watchInvocation: InvocationListener = Interceptor.attach(matchedMethod.address, {
      onLeave: (retval) => {

        switch (returnValue) {
          case true:
            if (retval.equals(TRUE)) {
              return;
            }
            send(
              c.blackBright(`[${job.identifier}] `) +
              `${c.green(selector)} ` +
              `Return value was: ${c.red(retval.toString())}, overriding to ${c.green(TRUE.toString())}`,
            );
            retval.replace(TRUE);
            break;

          case false:
            if (retval.equals(FALSE)) {
              return;
            }
            send(
              c.blackBright(`[${job.identifier}] `) +
              `${c.green(selector)} ` +
              `Return value was: ${c.red(retval.toString())}, overriding to ${c.green(FALSE.toString())}`,
            );
            retval.replace(FALSE);
            break;
        }
      },
    });

    // register the job
    job.invocations.push(watchInvocation);
    jobs.add(job);
  };
}
