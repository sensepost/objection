// Attempts to take a screenshot of the current application
// and foreground view.

// init some types
var CGFloat = (Process.pointerSize === 4) ? 'float' : 'double';
var CGSize = [CGFloat, CGFloat];

// get objc objects
var UIWindow = ObjC.classes.UIWindow;
var UIGraphicsBeginImageContextWithOptions = new NativeFunction(
    Module.findExportByName('UIKit', 'UIGraphicsBeginImageContextWithOptions'),
    'void', [CGSize, 'bool', CGFloat]);
var UIGraphicsGetImageFromCurrentImageContext = new NativeFunction(
    Module.findExportByName('UIKit', 'UIGraphicsGetImageFromCurrentImageContext'),
    'pointer', []);
var UIGraphicsEndImageContext = new NativeFunction(
    Module.findExportByName('UIKit', 'UIGraphicsEndImageContext'), 'void', []);
var UIImagePNGRepresentation = new NativeFunction(
    Module.findExportByName('UIKit', 'UIImagePNGRepresentation'),
    'pointer', ['pointer']);

var view = UIWindow.keyWindow();
var bounds = view.bounds();
var size = bounds[1];

UIGraphicsBeginImageContextWithOptions(size, 0, 0);
// view.drawViewHierarchyInRect_afterScreenUpdates_(bounds, true);  // <-- crashes =(

var image = UIGraphicsGetImageFromCurrentImageContext();
UIGraphicsEndImageContext();

var png =  new ObjC.Object(UIImagePNGRepresentation(image));
var image_data = Memory.readByteArray(png.bytes(), png.length());

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'ios-keychaindump',
    data: {}
};

send(response, image_data);

// -- Sample Objective-C
//
// https://github.com/nowsecure/frida-screenshot \0/
//
// ref: https://stackoverflow.com/a/13559362
//
// UIGraphicsBeginImageContextWithOptions(self.view.bounds.size, self.view.opaque, 0.0);
// [self.myView.layer renderInContext:UIGraphicsGetCurrentContext()];
// UIImage *image = UIGraphicsGetImageFromCurrentImageContext();
// UIGraphicsEndImageContext();
//
// NSData *imageData = UIImageJPEGRepresentation(image, 1.0 ); //you can use PNG too
// [imageData writeToFile:@"image1.jpeg" atomically:YES];
