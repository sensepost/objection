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
