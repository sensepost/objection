import { colors as c } from "../lib/color.js";
import {
  getApplicationContext,
  wrapJavaPerform
} from "./lib/libjava.js";
import { ClipboardManager } from "./lib/types.js";

export const monitor = (): Promise<void> => {
  // -- Sample Java
  //
  // ClipboardManager f = (ClipboardManager)getApplicationContext().getSystemService(CLIPBOARD_SERVICE);
  // ClipData.Item i = f.getPrimaryClip().getItemAt(0);
  // Log.e("t", "?:" + i.getText());

  send(`${c.yellowBright("Warning!")} This module is still broken. A pull request fixing it would be awesome!`);

  // https://developer.android.com/reference/android/content/Context.html#CLIPBOARD_SERVICE
  const CLIPBOARD_SERVICE: string = "clipboard";

  // a variable for clipboard text
  let data: string;

  return wrapJavaPerform(() => {

    const clipboardManager: ClipboardManager = Java.use("android.content.ClipboardManager");
    const context = getApplicationContext();
    const clipboardHandle = context.getApplicationContext().getSystemService(CLIPBOARD_SERVICE);
    const cp = Java.cast(clipboardHandle, clipboardManager);

    setInterval(() => {

      const primaryClip = cp.getPrimaryClip();

      // Check if there is at least some data
      if (primaryClip == null || primaryClip.getItemCount() <= 0) {
        return;
      }

      // If we have managed to get the primary clipboard and there are
      // items stored in it, process an update.
      const currentString = primaryClip.getItemAt(0).coerceToText(context).toString();

      // If the data is the same, just stop.
      if (data === currentString) {
        return;
      }

      // Update the data with the new string and report back.
      data = currentString;

      send(`${c.blackBright(`[pasteboard-monitor]`)} Data: ${c.greenBright(data.toString())}`);

    }, 1000 * 5);
  });
};
