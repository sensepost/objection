import { wrapJavaPerform } from "./lib/libjava";

export namespace monitor {
  export const stringCanary = (can: string): Promise<void> => {
    return wrapJavaPerform(() => {

    });
  };
}
