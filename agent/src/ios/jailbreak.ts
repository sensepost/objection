import { Jobs } from "../lib/jobs";

// Attempts to disable Jailbreak detection.
// This seems like an odd thing to do on a device that is probably not
// jailbroken. However, in the case of a device losing a jailbreak due to
// an OS upgrade, some filesystem artifacts may still exist, causing some
// of the typical checks to incorrectly detect the jailbreak status!

// Hook NSFileManager calls and check if it is to a common path.
// TODO: Hook fopen too.
const jailbreakPaths = [
    "/Applications/Cydia.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSetttings.app",
    "/Applications/WinterBoard.app",
    "/Applications/blackra1n.app",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
    "/bin/bash",
    "/bin/sh",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/usr/bin/cycript",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/usr/libexec/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/usr/sbin/sshd",
    "/var/cache/apt",
    "/var/lib/cydia",
    "/var/log/syslog",
    "/var/tmp/cydia.log",
];

export class IosJailBreak {

    // to disable any invocation listeners we keep record
    // of them in an array.
    private invocations: InvocationListener[] = [];

    constructor(private jobs: Jobs) { }

    public disable(): void {

        const jobIdentifier: string = this.jobs.identifier;

        this.invocations.push(
            Interceptor.attach(
                ObjC.classes.NSFileManager["- fileExistsAtPath:"].implementation, {
                    onEnter(args) {

                        // Use a marker to check onExit if we need to manipulate
                        // the response.
                        this.is_common_path = false;

                        // Extract the path
                        this.path = new ObjC.Object(args[2]).toString();

                        // check if the looked up path is in the list of common_paths
                        if (jailbreakPaths.indexOf(this.path) >= 0) {

                            // Mark this path as one that should have its response
                            // modified if needed.
                            this.is_common_path = true;
                        }
                    },
                    onLeave(retval) {

                        // check if the method call matched a common_path or if
                        // the lookup actually failed. we dont want to mess with
                        // paths that may not be part of jailbreak detection
                        // anyways.
                        if (!this.is_common_path || retval.isNull()) { return; }

                        send({
                            data: `A successful lookup for ${this.path} occurred. Marking it as failed.`,
                            error_reason: NaN,
                            status: "success",
                            type: "jailbreak-bypass",
                        });

                        // nope.exe
                        retval.replace(new NativePointer(0x00));
                    },
                }),
        );

        // Hook fork() in libSystem.B.dylib and return 0
        // TODO: Hook vfork
        const libSystemBdylibFork: NativePointer = Module.findExportByName("libSystem.B.dylib", "fork");

        // iOS simulator does hot have libSystem.B.dylib
        if (libSystemBdylibFork) {

            this.invocations.push(
                Interceptor.attach(libSystemBdylibFork, {
                    onLeave(retval) {

                        send({
                            data: "Making call to libSystem.B.dylib::fork() return 0x0",
                            error_reason: NaN,
                            status: "success",
                            type: "jailbreak-bypass",
                        });

                        retval.replace(new NativePointer(0x0));
                    },
                }),
            );
        }

        this.jobs.add(jobIdentifier, this.invocations, "ios jailbreak disable");
        this.invocations = [];
    }
}
