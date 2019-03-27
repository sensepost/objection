import { colors as c } from "../lib/color";
import { wrapJavaPerform } from "./lib/libjava";

export namespace heap {
  export const printInstances = (clazz: string): Promise<void> => {
    return wrapJavaPerform(() => {
      // tslint:disable:only-arrow-functions
      // tslint:disable:object-literal-shorthand
      // tslint:disable:no-empty
      Java.choose(clazz, {
        onComplete: function() {
          c.log(`\nClass instance enumeration complete for ${c.green(clazz)}`);
        },
        onMatch: function(instance) {
          c.log(`${c.greenBright(clazz)}: ${instance.toString()}`);
        },
      });
      // tslint:enable
    });
  };
}
