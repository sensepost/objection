import { wrapJavaPerform, getApplicationContext } from "./lib/libjava";

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
}