// NSMutableDictionary *result = [[NSMutableDictionary alloc] initWithContentsOfFile:path];

var NSMutableDictionary = ObjC.classes.NSMutableDictionary;

var data = NSMutableDictionary.alloc().initWithContentsOfFile_("{{ plist }}");

var response = {
    status: "success",
    error_reason: NaN,
    type: "plist-get",
    data: data.toString() 
}

send(JSON.stringify(response));
