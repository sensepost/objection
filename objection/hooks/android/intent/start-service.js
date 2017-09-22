// Launches a new Android service, starting a new task stack.

var ActivityThread = Java.use('android.app.ActivityThread');
var FLAG_ACTIVITY_NEW_TASK = 0x10000000;

var currentApplication = ActivityThread.currentApplication();
var context = currentApplication.getApplicationContext();

// Setup a new Intent
var Intent = Java.use('android.content.Intent');

// Get the Activity class's .class
var new_service = Java.use('{{ intent_class }}').class;

// Init and launch the intent
var intent = Intent.$new(context, new_service);

intent.setFlags(FLAG_ACTIVITY_NEW_TASK);
context.startService(intent);

// -- Sample Java
//
// Intent intent = new Intent(this, Service.class);
// intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
//
// startService(intent);
