import { colors as c } from "../lib/color.js";
import {
  getApplicationContext,
  wrapJavaPerform
} from "./lib/libjava.js";
import { Intent, FridaOverload } from "./lib/types.js";
import { analyseIntent } from "./lib/intentUtils.js";

// https://developer.android.com/reference/android/content/Intent.html#FLAG_ACTIVITY_NEW_TASK
const FLAG_ACTIVITY_NEW_TASK = 0x10000000;

// starts an Android activity
// This method does not yet allow for 'extra' data to be send along
// with the intent.
export const startActivity = (activityClass: string): Promise<void> => {
  // -- Sample Java
  //
  // Intent intent = new Intent(this, DisplayMessageActivity.class);
  // intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
  //
  // startActivity(intent);
  return wrapJavaPerform(() => {
    const context = getApplicationContext();

    // Setup a new Intent
    const androidIntent: Intent = Java.use("android.content.Intent");

    // Get the Activity class's .class
    const newActivity: Java.Wrapper = Java.use(activityClass).class;
    send(`Starting activity ${c.green(activityClass)}...`);

    // Init and launch the intent
    const newIntent: Intent = androidIntent.$new(context, newActivity);
    newIntent.setFlags(FLAG_ACTIVITY_NEW_TASK);

    context.startActivity(newIntent);
    send(c.blackBright(`Activity successfully asked to start.`));
  });
};

// starts an Android service
export const startService = (serviceClass: string): Promise<void> => {
  // -- Sample Java
  //
  // Intent intent = new Intent(this, Service.class);
  // intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
  //
  // startService(intent);
  return wrapJavaPerform(() => {
    const context = getApplicationContext();

    // Setup a new Intent
    const androidIntent: Intent = Java.use("android.content.Intent");

    // Get the Activity class's .class
    const newService: string = Java.use(serviceClass).$className;
    send(`Starting service ${c.green(serviceClass)}...`);

    // Init and launch the intent
    const newIntent: Intent = androidIntent.$new(context, newService);
    newIntent.setFlags(FLAG_ACTIVITY_NEW_TASK);

    context.startService(newIntent);
    send(c.blackBright(`Service successfully asked to start.`));
  });
};

// Analyzes and Detects Android Implicit Intents
// https://developer.android.com/guide/components/intents-filters#Types
export const analyzeImplicits = (): Promise<void> => {


  return wrapJavaPerform(() => {
    const classesToHook = [
      { className: "android.app.Activity", methodName: "startActivityForResult" },
      { className: "android.app.Activity", methodName: "onActivityResult" },
      { className: "androidx.activity.ComponentActivity", methodName: "onActivityResult" },
      { className: "android.content.Context", methodName: "startActivity"},
      { className: "android.content.BroadcastReceiver", methodName: "onReceive"}
      // Add other classes and methods as needed
    ];

    classesToHook.forEach(hook => {
      try {
        const clazz = Java.use(hook.className);
        const method = clazz[hook.methodName];
        method.overloads.forEach((overload: FridaOverload) => {
          overload.implementation = function (...args: any[]): any {
            args.forEach(arg => {
              if (arg && arg.$className === "android.content.Intent") {
                analyseIntent(`${hook.className}::${hook.methodName}`, arg);
              }
            });
            return overload.apply(this, args);
          };
        });
      } catch (e) {
        send(`[-] Error hooking ${c.redBright(`${hook.className}.${hook.methodName}: ${e}`)}`);
      }
    });
  });
};