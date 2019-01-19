import { colors as c } from "../lib/color";
import { getApplicationContext, wrapJavaPerform } from "./lib/libjava";
import { JavaClass } from "./lib/types";

export namespace intent {

  // https://developer.android.com/reference/android/content/Intent.html#FLAG_ACTIVITY_NEW_TASK
  const FLAG_ACTIVITY_NEW_TASK = 0x10000000;

  // starts an Android activity
  // This method does not year allow for 'extra' data to be send along
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
      const Intent: JavaClass = Java.use("android.content.Intent");

      // Get the Activity class's .class
      const newActivity: string = Java.use(activityClass).class;
      send(`Starting activity ${c.green(activityClass)}...`);

      // Init and launch the intent
      const newIntent: JavaClass = Intent.$new(context, newActivity);
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
      const Intent: JavaClass = Java.use("android.content.Intent");

      // Get the Activity class's .class
      const newService: string = Java.use(serviceClass).class;
      send(`Starting service ${c.green(serviceClass)}...`);

      // Init and launch the intent
      const newIntent: JavaClass = Intent.$new(context, newService);
      newIntent.setFlags(FLAG_ACTIVITY_NEW_TASK);

      context.startService(newIntent);
      send(c.blackBright(`Service successfully asked to start.`));
    });
  };
}
