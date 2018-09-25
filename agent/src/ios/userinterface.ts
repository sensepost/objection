import sc = require("frida-screenshot");

export namespace userinterface {

  export const screenshot = (): any => {
    // heavy lifting thanks to frida-screenshot!
    // https://github.com/nowsecure/frida-screenshot
    return sc();
  };

  export const alert = (message: string): void => {
    const { UIAlertController, UIAlertAction, UIApplication } = ObjC.classes;

    // Defining a Block that will be passed as handler parameter
    // to +[UIAlertAction actionWithTitle:style:handler:]
    const handler: ObjC.Block = new ObjC.Block({
      argTypes: ["object"],
      implementation: () => { return; },
      retType: "void",
    });

    // Using Grand Central Dispatch to pass messages (invoke methods) in application's main thread
    ObjC.schedule(ObjC.mainQueue, () => {

      // Using integer numerals for preferredStyle which is of type enum UIAlertControllerStyle
      const alertController: ObjC.Object = UIAlertController.alertControllerWithTitle_message_preferredStyle_(
        "Alert", message, 1);

      // Again using integer numeral for style parameter that is enum
      const okButton: ObjC.Object = UIAlertAction.actionWithTitle_style_handler_("OK", 0, handler);
      alertController.addAction_(okButton);

      // Instead of using `ObjC.choose()` and looking for UIViewController instances
      // on the heap, we have direct access through UIApplication:
      UIApplication.sharedApplication().keyWindow()
          .rootViewController().presentViewController_animated_completion_(alertController, true, NULL);
    });
  };

  export const dump = (): string => {
    return ObjC.classes.UIWindow.keyWindow().recursiveDescription().toString();
  };
}
