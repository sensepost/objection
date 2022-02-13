import { wrapJavaPerform } from "./lib/libjava";

export const deoptimize = (): Promise<void> => {
  return wrapJavaPerform(() => {
    Java.deoptimizeEverything();
  });
};
