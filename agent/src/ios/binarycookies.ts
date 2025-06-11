import { ObjC } from "../ios/lib/libobjc.js";
import { IIosCookie } from "./lib/interfaces.js";
import {
  NSArray,
  NSData,
  NSHTTPCookieStorage
} from "./lib/types.js";


export const get = (): IIosCookie[] => {

  // -- Sample Objective-C
  //
  // NSHTTPCookieStorage *cs = [NSHTTPCookieStorage sharedHTTPCookieStorage];
  // NSArray *cookies = [cs cookies];
  const cookies: IIosCookie[] = [];

  const HTTPCookieStorage = ObjC.classes.NSHTTPCookieStorage;
  const cookieStore: NSHTTPCookieStorage = HTTPCookieStorage.sharedHTTPCookieStorage();
  const cookieJar: NSArray = cookieStore.cookies();

  if (cookieJar.count() <= 0) {
    return cookies;
  }

  for (let i = 0; i < cookieJar.count(); i++) {

    // get the actual cookie from the jar
    const cookie: NSData = cookieJar.objectAtIndex_(i);

    // <NSHTTPCookie version:0 name:"__cfduid" value:"d2546c60b09a710a151d974e662f40c081498064665"
    // expiresDate:2018-06-21 17:04:25 +0000 created:2017-06-21 17:04:26 +0000 sessionOnly:FALSE
    // domain:".swapi.co" partition:"none" path:"/" isSecure:FALSE>
    const cookieData: IIosCookie = {
      domain: cookie.domain().toString(),
      expiresDate: cookie.expiresDate() ? cookie.expiresDate().toString() : "null",
      isHTTPOnly: cookie.isHTTPOnly().toString(),
      isSecure: cookie.isSecure().toString(),
      name: cookie.name().toString(),
      path: cookie.path().toString(),
      value: cookie.value().toString(),
      version: cookie.version().toString(),
    };

    cookies.push(cookieData);
  }

  return cookies;
};
