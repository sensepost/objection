import { colors as c } from "../lib/color";
import { IHeapClassDictionary, IHeapObject, IJavaField } from "./lib/interfaces";
import { wrapJavaPerform } from "./lib/libjava";

export namespace heap {

  // matches contains handles to methods, populated
  // by getInstances().
  export let handles: IHeapClassDictionary = {};

  const getInstance = (handle: string): Java.Wrapper | null => {
    const matches: IHeapObject[] = [];

    // Search for this handle, and push the results to matches
    Object.keys(handles).forEach((clazz) => {
      handles[clazz].filter((heapObject) => {
        if (heapObject.handleString === handle) {
          matches.push(heapObject);
        }
      });
    });

    if (matches.length > 1) {
      c.log(`Found ${c.redBright(matches.length.toString())} handles, this is probably a bug, please report it!`);
    }

    if (matches.length > 0) {
      c.log(`${c.blackBright(`Handle ` + handle + ` is to class `)}${c.greenBright(matches[0].className)}`);
      return matches[0].handle;
    }

    c.log(`${c.yellowBright(`Warning:`)} Could not find a known handle for ${handle}. ` +
      `Try searching class instances first.`);

    return null;
  };

  export const getInstances = (clazz: string, fresh: boolean = false): Promise<IHeapObject[]> => {
    return wrapJavaPerform(() => {

      if (handles.hasOwnProperty(clazz) && handles[clazz].length > 0 && !fresh) {
        c.log(c.blackBright(`Using exsiting matches for ${clazz}. Use --fresh flag for new instances.`));
        return handles[clazz];
      }

      // A fresh search should be done! Clean up first
      handles[clazz] = [];

      // tslint:disable:only-arrow-functions
      // tslint:disable:object-literal-shorthand
      // tslint:disable:no-empty
      Java.choose(clazz, {
        onComplete: function() {
          c.log(`Class instance enumeration complete for ${c.green(clazz)}`);
        },
        onMatch: function(instance) {
          handles[clazz].push({
            asString: instance.toString(),
            className: instance.$className,
            handle: instance,
            handleString: instance.$handle.toString(),
          });
        },
      });
      // tslint:enable

      return handles[clazz];
    });
  };

  export const methods = (handle: string): Promise<string[]> => {
    return wrapJavaPerform(() => {
      const clazz: Java.Wrapper = getInstance(handle);
      if (clazz == null) {
        return [];
      }

      return clazz.class.getDeclaredMethods().map((method) => {
        return method.toGenericString();
      });
    });
  };

  export const execute = (handle: string, method: string, returnString: boolean = false): Promise<string | null> => {
    return wrapJavaPerform(() => {
      const clazz: Java.Wrapper = getInstance(handle);

      if (clazz == null) {
        return;
      }

      c.log(`${c.blackBright(`Executing method:`)} ${c.greenBright(`${method}()`)}`);
      const returnValue = clazz[method]();

      if (returnString && returnValue) {
        return returnValue.toString();
      }

      return returnValue;
    });
  };

  export const fields = (handle: string): Promise<IJavaField[]> => {
    return wrapJavaPerform(() => {
      const clazz: Java.Wrapper = getInstance(handle);

      if (clazz == null) {
        return;
      }

      return clazz.class.getDeclaredFields().map((field): IJavaField => {
        const fieldName: string = field.getName();
        const fieldInstance: Java.Wrapper = clazz.class.getDeclaredField(fieldName);
        fieldInstance.setAccessible(true);

        let fieldValue = fieldInstance.get(clazz);

        // Cast a string if possible
        if (fieldValue) {
          fieldValue = fieldValue.toString();
        }

        return {
          name: fieldName,
          value: fieldValue,
        };
      });
    });
  };

  export const evaluate = (handle: string, js: string): Promise<void> => {
    return wrapJavaPerform(() => {
      const clazz: Java.Wrapper = getInstance(handle);

      if (clazz == null) {
        return;
      }

      // tslint:disable-next-line:no-eval
      eval(js);
    });
  };
}
