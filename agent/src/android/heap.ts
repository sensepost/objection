import { colors as c } from "../lib/color";
import { IHeapObject } from "./lib/interfaces";
import { wrapJavaPerform } from "./lib/libjava";

export namespace heap {
  export const getInstances = (clazz: string): Promise<Java.Wrapper[]> => {
    return wrapJavaPerform(() => {

      const matches: IHeapObject[] = [];

      // tslint:disable:only-arrow-functions
      // tslint:disable:object-literal-shorthand
      // tslint:disable:no-empty
      Java.choose(clazz, {
        onComplete: function() {
          c.log(`Class instance enumeration complete for ${c.green(clazz)}`);
        },
        onMatch: function(instance) {
          matches.push({
            asString: instance.toString(),
            className: instance.$className,
            handle: instance,
            handleString: instance.$handle,
          });
        },
      });
      // tslint:enable

      return matches;
    });
  };
}
