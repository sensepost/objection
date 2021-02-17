# Attempt to download additional temporary SQLite files for DB inspection

Android apps have been found to use 'Write-Ahead-Log' and 'Shared-Memory'
SQLite functionality. If the respective files aren't downloaded for local 
inspection, database entries would be missing.

## Test app TikTok for Android without patch

Tables/DB entries missing:

```
root@who-knows:~/research/android/frida# objection --gadget com.zhiliaoapp.musically explore
Using USB device `GT-I9300`
Agent injected and responds ok!

     _   _         _   _
 ___| |_|_|___ ___| |_|_|___ ___
| . | . | | -_|  _|  _| | . |   |
|___|___| |___|___|_| |_|___|_|_|
      |___|(object)inject(ion) v1.9.5

     Runtime Mobile Exploration
        by: @leonjza from @sensepost

[tab] for command suggestions
com.zhiliaoapp.musically on (samsung: 7.1.2) [usb] # cd ..                                                                                                                                                         
/data/user/0/com.zhiliaoapp.musically
com.zhiliaoapp.musically on (samsung: 7.1.2) [usb] # cd databases                                                                                                                                                  
/data/user/0/com.zhiliaoapp.musically/databases
com.zhiliaoapp.musically on (samsung: 7.1.2) [usb] # sqlite connect androidx.work.workdb                                                                                                                           
Caching local copy of database file...
Downloading /data/user/0/com.zhiliaoapp.musically/databases/androidx.work.workdb to /tmp/tmpk7_eoerg.sqlite
Streaming file from device...
Writing bytes to destination...
Successfully downloaded /data/user/0/com.zhiliaoapp.musically/databases/androidx.work.workdb to /tmp/tmpk7_eoerg.sqlite
Validating SQLite database format
Connected to SQLite database at: androidx.work.workdb
SQLite @ androidx.work.workdb > .tables                                                                                                                                                                            
Time: 0.001s
SQLite @ androidx.work.workdb >  

```

## Test app TikTok for Android with patch

No tables/DB entries missing:


```
root@who-knows:~/research/android/frida# objection --gadget com.zhiliaoapp.musically explore
Using USB device `GT-I9300`
Agent injected and responds ok!

     _   _         _   _
 ___| |_|_|___ ___| |_|_|___ ___
| . | . | | -_|  _|  _| | . |   |
|___|___| |___|___|_| |_|___|_|_|
      |___|(object)inject(ion) v1.9.5

     Runtime Mobile Exploration
        by: @leonjza from @sensepost

[tab] for command suggestions
com.zhiliaoapp.musically on (samsung: 7.1.2) [usb] # sqlite connect androidx.work.workdb                                                                                                                           
Caching local copy of database file...
Downloading /data/user/0/com.zhiliaoapp.musically/files/androidx.work.workdb to /tmp/tmpgc5zr1bj.sqlite
Unable to download file. Target path is not readable.
Validating SQLite database format
File does not appear to be a SQLite3 db. Try downloading and manually inspecting this one.
com.zhiliaoapp.musically on (samsung: 7.1.2) [usb] # cd ..                                                                                                                                                         
/data/user/0/com.zhiliaoapp.musically
com.zhiliaoapp.musically on (samsung: 7.1.2) [usb] # cd databases                                                                                                                                                  
/data/user/0/com.zhiliaoapp.musically/databases
com.zhiliaoapp.musically on (samsung: 7.1.2) [usb] # sqlite connect androidx.work.workdb                                                                                                                           
Caching local copy of database file...
Downloading /data/user/0/com.zhiliaoapp.musically/databases/androidx.work.workdb to /tmp/tmpuee0o3pf.sqlite
Streaming file from device...
Writing bytes to destination...
Successfully downloaded /data/user/0/com.zhiliaoapp.musically/databases/androidx.work.workdb to /tmp/tmpuee0o3pf.sqlite
... caching local copy of database "shm" file...
Downloading /data/user/0/com.zhiliaoapp.musically/databases/androidx.work.workdb-shm to /tmp/tmpuee0o3pf.sqlite-shm
Streaming file from device...
Writing bytes to destination...
Successfully downloaded /data/user/0/com.zhiliaoapp.musically/databases/androidx.work.workdb-shm to /tmp/tmpuee0o3pf.sqlite-shm
... caching local copy of database "wal" file...
Downloading /data/user/0/com.zhiliaoapp.musically/databases/androidx.work.workdb-wal to /tmp/tmpuee0o3pf.sqlite-wal
Streaming file from device...
Writing bytes to destination...
Successfully downloaded /data/user/0/com.zhiliaoapp.musically/databases/androidx.work.workdb-wal to /tmp/tmpuee0o3pf.sqlite-wal
Validating SQLite database format
Connected to SQLite database at: androidx.work.workdb
SQLite @ androidx.work.workdb > .tables                                                                                                                                                                            
+-------------------+
| name              |
+-------------------+
| Dependency        |
| SystemIdInfo      |
| WorkName          |
| WorkSpec          |
| WorkTag           |
| android_metadata  |
| room_master_table |
+-------------------+
Time: 0.030s
SQLite @ androidx.work.workdb >  
```


