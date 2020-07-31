import { colors as c } from "../lib/color";
import { IHeapClassDictionary, IHeapObject, IJavaField, IHeapNormalised } from "./lib/interfaces";
import { wrapJavaPerform } from "./lib/libjava";

export namespace heap {

  export let handles: IHeapClassDictionary = {};

  const getInstance = (hashcode: number): Java.Wrapper | null => {
    const matches: IHeapObject[] = [];

    // Search for this handle, and push the results to matches
    Object.keys(handles).forEach((clazz) => {
      handles[clazz].filter((heapObject) => {
        if (heapObject.hashcode === hashcode) {
          matches.push(heapObject);
        }
      });
    });

    if (matches.length > 1) {
      c.log(`Found ${c.redBright(matches.length.toString())} handles, this is probably a bug, please report it!`);
    }

    if (matches.length > 0) {
      wrapJavaPerform(() => {
        c.log(`${c.blackBright(`Handle ` + hashcode + ` is to class `)}
        ${c.greenBright(matches[0].instance.$className)}`);
      });
      return matches[0].instance;
    }

    c.log(`${c.yellowBright(`Warning:`)} Could not find a known handle for ${hashcode}. ` +
      `Try searching class instances first.`);

    return null;
  };

  export const getInstances = (clazz: string): Promise<any[]> => {
    return wrapJavaPerform(() => {

      handles[clazz] = [];

      // tslint:disable:only-arrow-functions
      // tslint:disable:object-literal-shorthand
      // tslint:disable:no-empty
      Java.choose(clazz, {
        onComplete: function () {
          c.log(`Class instance enumeration complete for ${c.green(clazz)}`);
        },
        onMatch: function (instance) {
          handles[clazz].push({
            instance: instance,
            hashcode: instance.hashCode(),
          });
        },
      });
      // tslint:enable

      return handles[clazz].map((h): IHeapNormalised => {
        return {
          hashcode: h.hashcode,
          classname: clazz,
          tostring: h.instance.toString(),
        }
      });
    });
  };

  export const methods = (handle: number): Promise<string[]> => {
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

  export const execute = (handle: number, method: string, returnString: boolean = false): Promise<string | null> => {
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

  export const fields = (handle: number): Promise<IJavaField[]> => {
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

  export const evaluate = (handle: number, js: string): Promise<void> => {
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
