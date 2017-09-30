// Monitors the Android Clipboard and reports changes to
// its contents.
//
// Ref: https://developer.android.com/guide/topics/text/copy-paste.html

var ActivityThread = Java.use('android.app.ActivityThread');
var ClipboardManager = Java.use('android.content.ClipboardManager');
var CLIPBOARD_SERVICE = 'clipboard';

var currentApplication = ActivityThread.currentApplication();
var context = currentApplication.getApplicationContext();

var clipboard_handle = context.getApplicationContext().getSystemService(CLIPBOARD_SERVICE);
var clipboard = Java.cast(clipboard_handle, ClipboardManager);

// Variable used for the current string data
var string_data;

function check_clipboard_data() {

    Java.perform(function () {

        var primary_clip = clipboard.getPrimaryClip();

        // If we have managed to get the primary clipboard and there are
        // items stored in it, process an update.
        if (primary_clip != null && primary_clip.getItemCount() > 0) {

            var data = primary_clip.getItemAt(0).coerceToText(context).toString();

            // If the data is the same, just stop.
            if (string_data == data) {
                return;
            }

            // Update the data with the new string and report back.
            string_data = data;

            send({
                status: 'success',
                error_reason: NaN,
                type: 'clipboard-monitor-string',
                data: data
            });
        }
    });
}

// Poll every 5 seconds
setInterval(check_clipboard_data, 1000 * 5);

// -- Sample Java
//
// ClipboardManager f = (ClipboardManager)getApplicationContext().getSystemService(CLIPBOARD_SERVICE);
// ClipData.Item i = f.getPrimaryClip().getItemAt(0);
// Log.e("t", "?:" + i.getText());
