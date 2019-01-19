import { colors as c } from "../lib/color";
import { wrapJavaPerform } from "./lib/libjava";

export namespace userinterface {

  // https://developer.android.com/reference/android/view/WindowManager.LayoutParams.html#FLAG_SECURE
  const FLAG_SECURE = 0x00002000;

  export const screenshot = (): Promise<any> => {
    return wrapJavaPerform(() => {
      // Take a screenshot by making use of a View's drawing cache:
      //  ref: https://developer.android.com/reference/android/view/View.html#getDrawingCache(boolean)
      const ActivityThread = Java.use("android.app.ActivityThread");
      const Activity = Java.use("android.app.Activity");
      const ActivityClientRecord = Java.use("android.app.ActivityThread$ActivityClientRecord");
      const Bitmap = Java.use("android.graphics.Bitmap");
      const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
      const CompressFormat = Java.use("android.graphics.Bitmap$CompressFormat");

      let bytes;

      const activityThread = ActivityThread.currentActivityThread();
      const activityRecords = activityThread.mActivities.value.values().toArray();
      let currentActivity;

      for (const i of activityRecords) {
        const activityRecord = Java.cast(activityRecords[i], ActivityClientRecord);

        if (!activityRecord.paused.value) {
          currentActivity = Java.cast(Java.cast(activityRecord, ActivityClientRecord).activity.value, Activity);
          break;
        }
      }

      if (currentActivity) {
        const view = currentActivity.getWindow().getDecorView().getRootView();
        view.setDrawingCacheEnabled(true);
        const bitmap = Bitmap.createBitmap(view.getDrawingCache());
        view.setDrawingCacheEnabled(false);

        const outputStream = ByteArrayOutputStream.$new();
        bitmap.compress(CompressFormat.PNG.value, 100, outputStream);
        bytes = outputStream.buf.value;
      }

      return bytes;
    });
  };

  export const setFlagSecure = (v: boolean): Promise<void> => {
    return wrapJavaPerform(() => {
      const ActivityThread = Java.use("android.app.ActivityThread");
      const Activity = Java.use("android.app.Activity");
      const ActivityClientRecord = Java.use("android.app.ActivityThread$ActivityClientRecord");

      const activityThread = ActivityThread.currentActivityThread();
      const activityRecords = activityThread.mActivities.value.values().toArray();
      let currentActivity;

      for (const i of activityRecords) {
        const activityRecord = Java.cast(i, ActivityClientRecord);
        if (!activityRecord.paused.value) {
          currentActivity = Java.cast(Java.cast(activityRecord, ActivityClientRecord).activity.value, Activity);
          break;
        }
      }

      if (currentActivity) {
        // Somehow the next line prevents Frida from throwing an abort error
        currentActivity.getWindow();
        // Set flag and trigger update (Throws abort without first calling getWindow())
        Java.scheduleOnMainThread(() => {
          currentActivity.getWindow().setFlags(v ? FLAG_SECURE : 0, FLAG_SECURE);
          send(`FLAG_SECURE set to ${c.green(v.toString())}`);
        });
      }
    });
  };
}
