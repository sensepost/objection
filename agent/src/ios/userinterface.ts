// tslint:disable-next-line:no-var-requires
const sc = require("frida-screenshot");
import { colors as c } from "../lib/color";
import { IJob } from "../lib/interfaces";
import { jobs } from "../lib/jobs";

export namespace userinterface {

  export const screenshot = (): any => {
    // heavy lifting thanks to frida-screenshot!
    // https://github.com/nowsecure/frida-screenshot
    return sc();
  };

  export const dump = (): string => {
    return ObjC.classes.UIWindow.keyWindow().recursiveDescription().toString();
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

  export const biometricsBypass = (): void => {
    // -- Sample Objective-C
    //
    // LAContext *myContext = [[LAContext alloc] init];
    // NSError *authError = nil;
    // NSString *myLocalizedReasonString = @"Please authenticate.";

    // if ([myContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&authError]) {
    //     [myContext evaluatePolicy:LAPolicyDeviceOwnerAuthentication
    //               localizedReason:myLocalizedReasonString
    //                         reply:^(BOOL success, NSError *error) {
    //                             if (success) {

    //                                 dispatch_async(dispatch_get_main_queue(), ^{
    //                                     [self performSegueWithIdentifier:@"LocalAuthSuccess" sender:nil];
    //                                 });

    //                             } else {

    //                                 dispatch_async(dispatch_get_main_queue(), ^{
    //                                     UIAlertView *alertView = [[UIAlertView alloc] initWithTitle:@"Error"
    //                                                                                         message:error.description
    //                                                                                         delegate:self
    //                                                                                cancelButtonTitle:@"OK"
    //                                                                                otherButtonTitles:nil, nil];
    //                                     [alertView show];
    //                                     // Rather than show a UIAlert here, use the
    //                                     // error to determine if you should push to a keypad for PIN entry.
    //                                 });
    //                             }
    //                         }];

    const job: IJob = {
      identifier: jobs.identifier(),
      invocations: [],
      type: "ios-biometrics-disable",
    };

    const lacontext: InvocationListener = Interceptor.attach(
      ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"].implementation, {
        onEnter(args) {

          // localizedReason:
          const reason = new ObjC.Object(args[3]);
          send(
            c.blackBright(`[${job.identifier}] `) + `Localized Reason for auth requirement: ` +
            c.green(reason.toString()),
          );

          // get the original block that should run on success for reply:
          // and save that block as a callback, to run once we change the reply
          // from the OS to a true
          const originalBlock = new ObjC.Block(args[4]);
          const savedReplyBlock = originalBlock.implementation;

          originalBlock.implementation = (success, error) => {
            send(
              c.blackBright(`[${job.identifier}] `) + `OS authentication response: ` +
              c.red(success),
            );

            if (!success === true) {
              send(
                c.blackBright(`[${job.identifier}] `) +
                c.greenBright("Marking OS response as True instead"),
              );

              // Change the success response from the OS to true
              success = true;
            }

            // and run the original block
            savedReplyBlock(success, error);

            send(
              c.blackBright(`[${job.identifier}] `) +
              c.green("Biometrics bypass hook complete"),
            );
          };
        },
      });

    // register the job
    job.invocations.push(lacontext);
    jobs.add(job);
  };
}
