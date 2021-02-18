import { wrapJavaPerform } from "./lib/libjava"

export namespace general {

  export const deoptimize = (): Promise<void> => {
    return wrapJavaPerform(() => {
      Java.deoptimizeEverything();
    });
  }

}
