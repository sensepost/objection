import { colors as c } from "../lib/color";

export namespace pasteboard {
  export const monitor = (): void => {
    // -- Sample Objective-C
    //
    // UIPasteboard *pb = [UIPasteboard generalPasteboard];
    // NSLog(@"%@", [pb string]);
    // NSLog(@"%@", [pb image]);

    const UIPasteboard = ObjC.classes.UIPasteboard;
    const Pasteboard = UIPasteboard.generalPasteboard();
    let data: string = "";

    setInterval(() => {
      const currentString = Pasteboard.string().toString();

      // do nothing if the strings are the same as the last one
      // we know about
      if (currentString === data) { return; }

      // update the string_data with the new string
      data = currentString;

      // ... and send the update along
      send(`${c.blackBright(`[pasteboard-monitor]`)} Data: ${c.greenBright(data.toString())}`);

      // 5 second poll
    }, 1000 * 5);
  };
}
