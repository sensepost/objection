export interface IKeychainItem {
  item_class: string;
  create_date: string;
  modification_date: string;
  description: string;
  comment: string;
  creator: string;
  type: string;
  script_code: string;
  alias: string;
  invisible: string;
  negative: string;
  custom_icon: string;
  protected: string;
  access_control: string;
  accessible_attribute: string;
  entitlement_group: string;
  generic: string;
  service: string;
  account: string;
  label: string;
  data: string;
  dataHex: string;
}

export interface IIosFileSystem {
  files: any;
  path: string;
  readable: boolean;
  writable: boolean;
}

export interface IIosFilePath {
  attributes: any;
  fileName: string;
  readable: boolean | undefined;
  writable: boolean | undefined;
}

export interface IIosCookie {
  name: string;
  version: string;
  value: string;
  expiresDate: string | undefined;
  domain: string;
  path: string;
  isSecure: boolean;
  isHTTPOnly: boolean;
}

export interface ICredential {
  authMethod: string;
  host: string;
  password: string;
  port: string;
  protocol: string;
  user: string;
}

export interface IFramework {
  version: string | null;
  executable: string | null;
  bundle: string | null;
  path: string | null;
}

export interface IHeapObject {
  className: string;
  handle: string;
  ivars: any[string];
  kind: string;
  methods: string[];
  superClass: string;
}

export interface IBinaryModuleDictionary {
  [index: string]: IBinaryInfo;
}

export interface IBinaryInfo {
  encrypted: boolean;
  pie: boolean;
  rootSafe: boolean;
  stackExec: boolean;
  type: string;
}
