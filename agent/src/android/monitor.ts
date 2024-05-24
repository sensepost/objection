import { wrapJavaPerform } from "./lib/libjava.js";

export namespace monitor {
  export const stringCanary = (can: string): Promise<void> => {
    return wrapJavaPerform(() => {

    });
  };
}
