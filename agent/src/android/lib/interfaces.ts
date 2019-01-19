export interface IAndroidFilesystem {
    files: any;
    path: string;
    readable: boolean;
    writable: boolean;
}

export interface IExecutedCommand {
    command: string;
    stdOut: string;
    stdErr: string;
}

export interface IKeyStoreEntry {
    alias: string;
    is_certificate: boolean;
    is_key: boolean;
}
