#import "TwitterLoginPlugin.h"
#if __has_include(<twitter_sign_in/twitter_sign_in-Swift.h>)
#import <twitter_sign_in/twitter_sign_in-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "twitter_sign_in-Swift.h"
#endif

@implementation TwitterLoginPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftTwitterLoginPlugin registerWithRegistrar:registrar];
}
@end
