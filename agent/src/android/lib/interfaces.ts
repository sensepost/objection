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

export interface ICurrentActivityFragment {
    activivity: string | null;
    fragment: string | null;
}

export interface IHeapClassDictionary {
    [index: string]: IHeapObject[];
}

export interface IHeapObject {
    hashcode: number;
    instance: Java.Wrapper;
}

export interface IHeapNormalised {
    hashcode: number;
    classname: string;
    tostring: string;
}

export interface IJavaField {
    name: string;
    value: string;
}
