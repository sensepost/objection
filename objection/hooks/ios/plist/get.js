// Attempts to read a Plist as an Objective-C dictionary.

var NSMutableDictionary = ObjC.classes.NSMutableDictionary;

var data = NSMutableDictionary.alloc().initWithContentsOfFile_('{{ plist }}');

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'plist-get',
    data: data.toString() 
};

send(response);

// -- Sample Objective-C
//
// NSMutableDictionary *result = [[NSMutableDictionary alloc] initWithContentsOfFile:path];
