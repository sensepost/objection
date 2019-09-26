#import "libFlex.h"
#import "FlexManager.h"

@implementation libFlex

- (id)init
{
    self = [super init];
    return self;
}

- (void)logSomething:(NSString *)something
{
    NSLog(@"%@", something);
}

- (void)flexUp {

    [[FLEXManager sharedManager] showExplorer];
}

@end

static void __attribute__((constructor)) initialize(void){
    NSLog(@"==== Booted ====");
}
