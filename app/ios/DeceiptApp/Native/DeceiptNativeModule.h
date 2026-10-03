//
//  DeceiptNativeModule.h
//  Deceipt iOS native adapter (A4) — app target
//
//  The ObjC module class the RN TurboModule registry resolves as "DeceiptNative".
//  It builds a hand-written ObjCTurboModule subclass (DeceiptTurboModule) and
//  forwards every operation to the Swift `DeceiptNativeBackend`.
//
//  Why hand-written and not codegen: A3's `subscribe(listener) => () => void`
//  cannot be expressed as a codegen spec — `react-native-codegen` rejects a
//  function-returning method (`UnsupportedFunctionReturnTypeAnnotationParserError`).
//  `subscribe` therefore installs a real JSI listener (many-invocation) rather
//  than the one-shot callback the generic bridge converts JS functions into.
//

#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>
#import <ReactCommon/RCTTurboModule.h>

NS_ASSUME_NONNULL_BEGIN

@interface DeceiptNative : NSObject <RCTBridgeModule, RCTTurboModule>
@end

NS_ASSUME_NONNULL_END
