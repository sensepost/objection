import { getNSMainBundle } from "../ios/lib/helpers";
import { wrapJavaPerform, getApplicationContext } from "./lib/libjava";
import { ArrayList } from "./lib/types";

export namespace scanner {
    export const getfbdatabase = (): Promise<any> => {
        return wrapJavaPerform(() => {
            // -- Sample Java
            //
            // String dburl = (String)getString(R.string.firebase_database_url);
            const context = getApplicationContext();
            const myid = context.getResources().getIdentifier("firebase_database_url", "string", context.getPackageName());
            const dburl = context.getString(myid);
            return dburl;            
        });
    }
    export const getapikeys = (): Promise<string[]> => {
        return wrapJavaPerform(() => {
            const keynames = [
                "google_maps_geocoder_key",
                "notification_server_key",
                "server_key",
                "com.google.android.geo.API_KEY",
                "com.google.android.maps.v2.API_KEY",
                "googlePlacesWebApi",
                "google_crash_reporting_api_key",
                "google_api_key"
            ];
            const context = getApplicationContext();
            var keys : string[] = new Array;
            var count = 0;
            for (var i = 0; i < keynames.length; i++) {
                try {
                    var key = context.getResources().getIdentifier(keynames[i], "string", context.getPackageName());
                    keys[count] = context.getString(key);
                    count++;
                } catch (error) {
                    
                }
            }
            return keys;
        });
    }
}