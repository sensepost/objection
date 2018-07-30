export interface IFridaInfo {
  arch: string;
  debugger: boolean;
  heap: number;
  platform: string;
  version: string;
}

export interface IIosPackage {

  applicationName: string;
  deviceName: string;
  identifierForVendor: string;
  model: string;
  systemName: string;
  systemVersion: string;

}

export interface IAndroidPackage {
  application_name: string;
  board: string;
  brand: string;
  device: string;
  host: string;
  id: string;
  model: string;
  product: string;
  user: string;
  version: string;
}

export interface IIosBundlePaths {
  BundlePath: string;
  CachesDirectory: string;
  DocumentDirectory: string;
  LibraryDirectory: string;
}

export interface IJob {
  identifier: string;
  extra: string;
  invocations: InvocationListener[];
}
