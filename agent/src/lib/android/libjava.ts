export function getApplicationContext(): any {

    const ActivityThread = Java.use("android.app.ActivityThread");
    const currentApplication = ActivityThread.currentApplication();
    const context = currentApplication.getApplicationContext();

    return context;
}
