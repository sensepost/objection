import { ICredential } from "./lib/interfaces";
import { NSArray, NSData, NSURLCredentialStorage } from "./lib/types";

export namespace credentialstorage {

  export const dump = (): ICredential[] => {

    // -- Sample ObjC to create and dump a credential
    // NSURLProtectionSpace *ps = [[NSURLProtectionSpace alloc]
    //  initWithHost:@"foo.com" port:80 protocol:@"https" realm:NULL
    //  authenticationMethod:NSURLAuthenticationMethodHTTPBasic];
    // NSURLCredential *creds = [[NSURLCredential alloc]
    //  initWithUser:@"user" password:@"password" persistence:NSURLCredentialPersistencePermanent];
    // NSURLCredentialStorage *cs = [NSURLCredentialStorage sharedCredentialStorage];

    // [cs setCredential:creds forProtectionSpace:ps];

    // NSDictionary *allcreds = [cs allCredentials];
    // NSLog(@"%@", allcreds);

    const credentialStorage: NSURLCredentialStorage = ObjC.classes.NSURLCredentialStorage;
    const data: ICredential[] = [];
    const credentialsDict: NSArray = credentialStorage.sharedCredentialStorage().allCredentials();

    if (credentialsDict.count() <= 0) {
      return data;
    }

    const protectionSpaceEnumerator = credentialsDict.keyEnumerator();
    let urlProtectionSpace;

    // tslint:disable-next-line:no-conditional-assignment
    while ((urlProtectionSpace = protectionSpaceEnumerator.nextObject()) !== null) {

      const userNameEnumerator = credentialsDict.objectForKey_(urlProtectionSpace).keyEnumerator();
      let userName;

      // tslint:disable-next-line:no-conditional-assignment
      while ((userName = userNameEnumerator.nextObject()) !== null) {

        const creds: NSData = credentialsDict.objectForKey_(urlProtectionSpace).objectForKey_(userName);

        // Add the creds for this protection space.
        const credentialData: ICredential = {
          authMethod: urlProtectionSpace.authenticationMethod().toString(),
          host: urlProtectionSpace.host().toString(),
          password: creds.password().toString(),
          port: urlProtectionSpace.port(),
          protocol: urlProtectionSpace.protocol().toString(),
          user: creds.user().toString(),
        };

        data.push(credentialData);
      }
    }

    return data;
  };
}
