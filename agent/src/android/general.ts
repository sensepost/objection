import {
  wrapJavaPerform,
  Java
} from "./lib/libjava.js";

export const deoptimize = (): Promise<void> => {
  return wrapJavaPerform(() => {
    Java.deoptimizeEverything();
  });
};
