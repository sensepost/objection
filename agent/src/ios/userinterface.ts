// tslint:disable-next-line:no-var-requires
import { ObjC } from "../ios/lib/libobjc.js";
import type { default as ObjCTypes } from "frida-objc-bridge";
import screenshot from "frida-screenshot";
import { colors as c } from "../lib/color.js";
import * as jobs from "../lib/jobs.js";


export const take = (): any => {
  // heavy lifting thanks to frida-screenshot!
  // https://github.com/nowsecure/frida-screenshot
  return screenshot(null);
};

export const dump = (): string => {
  return ObjC.classes.UIWindow.keyWindow().recursiveDescription().toString();
};

export const alert = (message: string): void => {
  const { UIAlertController, UIAlertAction, UIApplication } = ObjC.classes;

  // Defining a Block that will be passed as handler parameter
  // to +[UIAlertAction actionWithTitle:style:handler:]
  const handler = new ObjC.Block({
    argTypes: ["object"],
    implementation: () => { return; },
    retType: "void",
  });

  // Using Grand Central Dispatch to pass messages (invoke methods) in application's main thread
  ObjC.schedule(ObjC.mainQueue, () => {

    // Using integer numerals for preferredStyle which is of type enum UIAlertControllerStyle
    const alertController: ObjCTypes.Object = UIAlertController.alertControllerWithTitle_message_preferredStyle_(
      "Alert", message, 1);

    // Again using integer numeral for style parameter that is enum
    const okButton: ObjCTypes.Object = UIAlertAction.actionWithTitle_style_handler_("OK", 0, handler);
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

  const policyJob: jobs.Job = new jobs.Job(jobs.identifier(), "ios-biometrics-disable-evaluatePolicy");

  const lacontext1: InvocationListener = Interceptor.attach(
    ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"].implementation, {
    onEnter(args) {

      // localizedReason:
      const reason = new ObjC.Object(args[3]);
      send(
        c.blackBright(`[${policyJob.identifier}] `) + `Localized Reason for auth requirement (evaluatePolicy): ` +
        c.green(reason.toString()),
      );

      // get the original block that should run on success for reply:
      // and save that block as a callback, to run once we change the reply
      // from the OS to a true
      const originalBlock = new ObjC.Block(args[4]);
      const savedReplyBlock = originalBlock.implementation;

      originalBlock.implementation = (success, error) => {
        send(
          c.blackBright(`[${policyJob.identifier}] `) + `OS authentication response: ` +
          c.red(success),
        );

        if (!success === true) {
          send(
            c.blackBright(`[${policyJob.identifier}] `) +
            c.greenBright("Marking OS response as True instead"),
          );

          // Change the success response from the OS to true
          success = true;
          error = null;
        }

        // and run the original block
        savedReplyBlock(success, error);

        send(
          c.blackBright(`[${policyJob.identifier}] `) +
          c.green("Biometrics bypass hook complete (evaluatePolicy)"),
        );
      };
    },
  });

  // register the job
  policyJob.addInvocation(lacontext1);
  jobs.add(policyJob);

  // -- Sample Swift
  // https://gist.github.com/algrid/f3f03915f264f243b9d06e875ad198c8/raw/03998319903ad9d939f85bbcc94ce9c23042b82b/KeychainBio.swift

  const accessControlJob: jobs.Job = new jobs.Job(jobs.identifier(), "ios-biometrics-disable-evaluateAccessControl");

  const lacontext2: InvocationListener = Interceptor.attach(
    ObjC.classes.LAContext["- evaluateAccessControl:operation:localizedReason:reply:"].implementation, {
    onEnter(args) {

      // localizedReason:
      const reason = new ObjC.Object(args[4]);
      send(
        c.blackBright(`[${accessControlJob.identifier}] `) + `Localized Reason for auth requirement (evaluateAccessControl): ` +
        c.green(reason.toString()),
      );

      // get the original block that should run on success for reply:
      // and save that block as a callback, to run once we change the reply
      // from the OS to a true
      const originalBlock = new ObjC.Block(args[5]);
      const savedReplyBlock = originalBlock.implementation;

      originalBlock.implementation = (success, error) => {
        send(
          c.blackBright(`[${accessControlJob.identifier}] `) + `OS authentication response: ` +
          c.red(success),
        );

        if (!success === true) {
          send(
            c.blackBright(`[${accessControlJob.identifier}] `) +
            c.greenBright("Marking OS response as True instead"),
          );

          // Change the success response from the OS to true
          success = true;
          error = null;
        }

        // and run the original block
        savedReplyBlock(success, error);

        send(
          c.blackBright(`[${accessControlJob.identifier}] `) +
          c.green("Biometrics bypass hook complete (evaluateAccessControl)"),
        );
      };
    },
  });

  // register the job
  accessControlJob.addInvocation(lacontext2);
  jobs.add(accessControlJob);
};
