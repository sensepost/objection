// Monitors the iOS pasteboard and reports changes to
// its contents.

var UIPasteboard = ObjC.classes.UIPasteboard;
var pasteboard = UIPasteboard.generalPasteboard();

var string_data;

// TODO: Monitor for images and plists
var image_data;
var plist_data;

function check_string_data() {

    var current_string = pasteboard.string().toString();

    // do nothing if the strings are the same as the last one
    // we know about
    if (current_string == string_data) {
        return;
    }

    // update the string_data with the new string
    string_data = current_string;

    // ... and send the update along
    send({
        status: 'success',
        error_reason: NaN,
        type: 'pasteboard-monitor-string',
        data: current_string
    });
}

// Poll every 5 seconds
setInterval(check_string_data, 1000 * 5);

// -- Sample Objective-C
//
// UIPasteboard *pb = [UIPasteboard generalPasteboard];
// NSLog(@"%@", [pb string]);
// NSLog(@"%@", [pb image]);
