// all Java calls need to be wrapped in a Java.perform().
// this helper just wraps that into a Promise that the
// rpc export will sniff and resolve before returning
// the result when its ready.
export const wrapJavaPerform = (fn: any): Promise<any> => {
  return new Promise((resolve, reject) => {
    Java.perform(() => {
      try {
        resolve(fn());
      } catch (e) {
        reject(e);
      }
    });
  });
};

export const getApplicationContext = (): any => {
  const ActivityThread = Java.use("android.app.ActivityThread");
  const currentApplication = ActivityThread.currentApplication();
  const context = currentApplication.getApplicationContext();

  return context;
};
