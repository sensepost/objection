import { colors as c } from "../../lib/color.js";

export const analyseIntent = (methodName: string, intent: Java.Wrapper): void => {
  try {
    send(`\nAnalyzing Intent from: ${c.green(`${methodName}`)}`);

    // Get Component
    const component = intent.getComponent();
    if (component) {
      send(`[-] ${c.green('Intent Type: Explicit Intent')}`);
    } else {
      send(`[+] ${c.redBright('Intent Type: Implicit Intent Detected!')}`);
      
      // Log intent details
      send(`[+] Action: ${ `${c.green(`${intent.getAction()}`)}` || `${c.redBright(`[None]`)}` }`);
      send(`[+] Data URI: ${ `${c.green(`${intent.getDataString()}`)}` || `${c.redBright(`[None]`)}` }`);
      send(`[+] Type: ${ `${c.green(`${intent.getType()}`)}` || `${c.redBright(`[None]`)}` }`);
      send(`[+] Flags: ${c.green(`0x${intent.getFlags().toString(16)}`)}`);

      // Categories
      const categories = intent.getCategories();
      if (categories) {
        send("\n[+] Categories:");
        const iterator = categories.iterator();
        while (iterator.hasNext()) {
          send(`[+] Category: ${c.green(`${iterator.next()}`)} `);
        }
      } else {
        send(`[-] Category: ${`${c.redBright(`[None]`)}`}`);
      }

      // Extras
      const extras = intent.getExtras();
      if (extras) {
        send(`[+] Extras: ${c.green(`${extras}`)}`);
      } else {
        send(`[-] Extras: ${`${c.redBright(`[None]`)}`}`);
      }

      // Resolving implicit intents
      const activityContext = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
      if (activityContext) {
        const packageManager = activityContext.getPackageManager();
        const resolveInfoList = packageManager.queryIntentActivities(intent, Java.use("android.content.pm.PackageManager").MATCH_ALL.value);

        send("[+] Responding apps:");
        for (let i = 0; i < resolveInfoList.size(); i++) {
          const resolveInfo = resolveInfoList.get(i);
          send(`[*] Resolve Info List at position ${i}: ${c.green(`${resolveInfo.toString()}`)}`);
        }
      } else {
        send("[-] No activity context available");
      }

    }
  } catch (e) {
    send(`[!] Error analyzing intent: ${e}`);
  }
};
