import { BundleType } from "./lib/constants.js";
import { IFramework } from "./lib/interfaces.js";
import {
  NSArray,
  NSBundle,
  NSDictionary
} from "./lib/types.js";


// https://developer.apple.com/documentation/foundation/nsbundle/1408056-allframeworks?language=objc
// https://developer.apple.com/documentation/foundation/nsbundle/1413705-allbundles?language=objc
export const getBundles = (type: BundleType): IFramework[] => {

  // -- Sample ObjC
  //
  // for (id ob in [NSBundle allBundles]) {
  //   NSDictionary *i = [ob infoDictionary];
  //   NSString *p = [ob bundlePath];
  //   NSLog(@"%@:%@ @ %@", [i objectForKey:@"CFBundleIdentifier"],
  //         [i objectForKey:@"CFBundleShortVersionString"], p);
  // }

  // Figure out which bundle type to enumerate
  let frameworks: NSArray;
  if (type === BundleType.NSBundleFramework) {
    frameworks = ObjC.classes.NSBundle.allFrameworks();
  } else if (type === BundleType.NSBundleAllBundles) {
    frameworks = ObjC.classes.NSBundle.allBundles();
  }

  const appBundles: IFramework[] = [];
  const frameworksLength: number = frameworks.count().valueOf();

  for (let i = 0; i !== frameworksLength; i++) {

    // get information about the bundle itself
    const bundle: NSBundle = frameworks.objectAtIndex_(i);
    const bundleInfo: NSDictionary = bundle.infoDictionary();

    // get values for the keys we are interested in
    const bundlePath: string = bundle.bundlePath();
    const CFBundleIdentifier: string = bundleInfo.objectForKey_("CFBundleIdentifier");
    const CFBundleShortVersionString: string = bundleInfo.objectForKey_("CFBundleShortVersionString");
    const CFBundleExecutable: string = bundleInfo.objectForKey_("CFBundleExecutable");

    appBundles.push({
      bundle: CFBundleIdentifier ? CFBundleIdentifier.toString() : null,
      executable: CFBundleExecutable ? CFBundleExecutable.toString() : null,
      path: bundlePath.toString(),
      version: CFBundleShortVersionString ? CFBundleShortVersionString.toString() : null,
    });
  }

  return appBundles;
};
