//
//  DeceiptNativeModule.mm
//  Deceipt iOS native adapter (A4) — app target
//
//  Bridges the JS module "DeceiptNative" to the Swift `DeceiptNativeBackend`.
//
//  This is a HAND-WRITTEN TurboModule. Codegen cannot be used: A3's
//  `subscribe(listener) => () => void` is rejected by react-native-codegen
//  (`UnsupportedFunctionReturnTypeAnnotationParserError: Function return cannot
//  have type 'FunctionTypeAnnotation'`), and the generic ObjC-arg bridge wraps
//  JS functions as ONE-SHOT RCTResponseSenderBlocks, which cannot express a
//  listener invoked many times.
//
//  `DeceiptTurboModuleJSI` is a C++ subclass of `ObjCTurboModule` (the JSI
//  class, not an ObjC class). Each method is its own raw JSI host function:
//    * args are converted with `TurboModuleConvertUtils::convertJSIValueToObjCObject`;
//    * Promise methods build a real JS Promise and resolve/reject through
//      `AsyncCallback` so the JS functions run on the JS thread;
//    * `subscribe` retains the JS listener and returns an `unsubscribe` function.
//
//  Operations and event names mirror `app/src/native/DeceiptNative.ts` exactly.
//

// Module imports must precede the Swift-generated header so the protocol
// declarations its interfaces conform to (CoreBluetooth delegates, the React
// app-delegate base) are visible.
#import <Foundation/Foundation.h>
#import <CoreBluetooth/CoreBluetooth.h>
#import <UIKit/UIKit.h>
#import <React/RCTBridgeModule.h>
#import <React_RCTAppDelegate/RCTDefaultReactNativeFactoryDelegate.h>

#import "DeceiptNativeModule.h"
#import "DeceiptApp-Swift.h"

#import <React/RCTUtils.h>
#import <ReactCommon/RCTTurboModule.h>
#import <ReactCommon/CallInvoker.h>
#import <ReactCommon/TurboModule.h>
#import <react/bridging/Function.h>
#import <jsi/jsi.h>

#import <memory>
#import <set>
#import <string>
#import <vector>

using namespace facebook;
using namespace facebook::react;

static dispatch_queue_t DeceiptModuleQueue(void)
{
  static dispatch_queue_t queue;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    queue = dispatch_queue_create("com.deceipt.native", DISPATCH_QUEUE_SERIAL);
  });
  return queue;
}

/// JSON-safe ObjC value (NSNull for nil) so the result can cross to JSI.
static id DeceiptCleanValue(id value)
{
  if (value == nil) {
    return [NSNull null];
  }
  if ([value isKindOfClass:[NSArray class]]) {
    NSMutableArray *out = [NSMutableArray array];
    for (id v in (NSArray *)value) {
      [out addObject:DeceiptCleanValue(v)];
    }
    return out;
  }
  if ([value isKindOfClass:[NSDictionary class]]) {
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    [(NSDictionary *)value enumerateKeysAndObjectsUsingBlock:^(id k, id v, BOOL *stop) {
      out[[k description]] = DeceiptCleanValue(v);
    }];
    return out;
  }
  return value;
}

/// Builds a JS Error carrying the frozen bridge error shape both at the top
/// level (`isBridgeError` reads name/code/fatal/retryable) and under `.bridge`.
static jsi::Value DeceiptMakeError(jsi::Runtime &rt, NSDictionary *bridge, NSString *message)
{
  jsi::Value errValue = rt.global()
                            .getPropertyAsFunction(rt, "Error")
                            .callAsConstructor(rt, jsi::String::createFromUtf8(rt, message.UTF8String));
  jsi::Object err = errValue.getObject(rt);
  err.setProperty(rt, "name", jsi::String::createFromUtf8(rt, "DeceiptBridgeError"));
  if (bridge != nil) {
    err.setProperty(rt, "bridge", TurboModuleConvertUtils::convertObjCObjectToJSIValue(rt, bridge));
  }
  return errValue;
}

static const std::set<std::string> &DeceiptMethodNames()
{
  static const std::set<std::string> methods = {
      "capabilities",         "permissionState",       "requestPermissions",     "openSettings",
      "merchantKeyStatus",    "merchantKeyGenerate",   "merchantKeyDelete",      "merchantPublicIdentity",
      "merchantSignReceipt",  "verifyReceiptContainer", "verifyCredential",      "mintBindingQr",
      "startMerchantSession", "beginTransfer",         "startScan",              "stopScan",
      "startCustomerSession", "acceptOffer",           "retryTransfer",          "sendReceiptAck",
      "cancelSession",        "stopSession",           "sessionSnapshot",
  };
  return methods;
}

// ---------------------------------------------------------------------------
// C++ JSI TurboModule
// ---------------------------------------------------------------------------

class DeceiptTurboModuleJSI : public ObjCTurboModule {
 public:
  DeceiptTurboModuleJSI(const ObjCTurboModule::InitParams &params, DeceiptNativeBackend *backend)
      : ObjCTurboModule(params), backend_(backend)
  {
    for (const auto &name : DeceiptMethodNames()) {
      methodMap_[name] = MethodMetadata{0, [](jsi::Runtime &, TurboModule &, const jsi::Value *, size_t) {
                                          return jsi::Value::undefined();
                                        }};
    }
  }

  jsi::Value create(jsi::Runtime &runtime, const jsi::PropNameID &propName) override
  {
    std::string name = propName.utf8(runtime);

    if (name == "subscribe") {
      DeceiptNativeBackend *backend = backend_;
      auto invoker = jsInvoker_;
      return jsi::Function::createFromHostFunction(
          runtime, propName, 1,
          [backend, invoker](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args, size_t count) -> jsi::Value {
            if (count < 1 || !args[0].isObject() || !args[0].getObject(rt).isFunction(rt)) {
              return jsi::Value::undefined();
            }
            auto listener = std::make_shared<AsyncCallback<>>(
                AsyncCallback<>({rt, args[0].getObject(rt).getFunction(rt), invoker}));
            backend.nativeEventSink = ^(NSArray *batch) {
              id clean = DeceiptCleanValue(batch);
              listener->call([clean](jsi::Runtime &rt, jsi::Function &fn) {
                fn.call(rt, TurboModuleConvertUtils::convertObjCObjectToJSIValue(rt, clean));
              });
            };
            return jsi::Function::createFromHostFunction(
                rt, jsi::PropNameID::forAscii(rt, "unsubscribe"), 0,
                [backend](jsi::Runtime &, const jsi::Value &, const jsi::Value *, size_t) -> jsi::Value {
                  backend.nativeEventSink = nil;
                  return jsi::Value::undefined();
                });
          });
    }

    if (DeceiptMethodNames().count(name) == 0) {
      return TurboModule::create(runtime, propName);
    }

    DeceiptNativeBackend *backend = backend_;
    auto invoker = jsInvoker_;
    std::string methodName = name;

    return jsi::Function::createFromHostFunction(
        runtime, propName, 0,
        [backend, invoker, methodName](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,
                                       size_t count) -> jsi::Value {
          NSMutableArray *jsArgs = [NSMutableArray arrayWithCapacity:count];
          for (size_t i = 0; i < count; i++) {
            id converted = TurboModuleConvertUtils::convertJSIValueToObjCObject(rt, args[i], invoker, NO);
            [jsArgs addObject:DeceiptCleanValue(converted)];
          }

          jsi::Function Promise = rt.global().getPropertyAsFunction(rt, "Promise");
          auto executor = jsi::Function::createFromHostFunction(
              rt, jsi::PropNameID::forAscii(rt, "executor"), 2,
              [backend, invoker, methodName, jsArgs](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,
                                                     size_t) -> jsi::Value {
                auto resolveCb = std::make_shared<AsyncCallback<>>(
                    AsyncCallback<>({rt, args[0].getObject(rt).getFunction(rt), invoker}));
                auto rejectCb = std::make_shared<AsyncCallback<>>(
                    AsyncCallback<>({rt, args[1].getObject(rt).getFunction(rt), invoker}));

                dispatch_async(DeceiptModuleQueue(), ^{
                  NSError *error = nil;
                  id result = [backend dispatchMethodName:@(methodName.c_str()) args:jsArgs error:&error];
                  if (result != nil) {
                    id clean = DeceiptCleanValue(result);
                    resolveCb->call([clean](jsi::Runtime &rt, jsi::Function &fn) {
                      fn.call(rt, TurboModuleConvertUtils::convertObjCObjectToJSIValue(rt, clean));
                    });
                  } else if (error != nil) {
                    NSDictionary *bridge = error.userInfo[@"bridge"];
                    NSString *message = error.localizedDescription ?: @"native bridge failure";
                    rejectCb->call([bridge, message](jsi::Runtime &rt, jsi::Function &fn) {
                      fn.call(rt, DeceiptMakeError(rt, bridge, message));
                    });
                  } else {
                    rejectCb->call([methodName](jsi::Runtime &rt, jsi::Function &fn) {
                      fn.call(rt, DeceiptMakeError(rt, nil, [NSString stringWithFormat:@"%s failed", methodName.c_str()]));
                    });
                  }
                });
                return jsi::Value::undefined();
              });
          return Promise.callAsConstructor(rt, executor);
        });
  }

 private:
  /// Strong reference to the Swift backend (invalidated on module teardown).
  __strong DeceiptNativeBackend *backend_;
};

// ---------------------------------------------------------------------------
@implementation DeceiptNative {
  DeceiptNativeBackend *_backend;
}

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

- (instancetype)init
{
  if (self = [super init]) {
    _backend = [DeceiptNativeBackend new];
    // The PoC does not run BLE in the background; leaving the foreground ends
    // sessions cleanly rather than leaving a suspended radio mid-session.
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(appDidEnterBackground)
                                                 name:UIApplicationDidEnterBackgroundNotification
                                               object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(appDidEnterBackground)
                                                 name:UIApplicationWillTerminateNotification
                                               object:nil];
  }
  return self;
}

- (void)appDidEnterBackground
{
  [_backend handleAppState:@"background"];
}

- (std::shared_ptr<TurboModule>)getTurboModule:(const ObjCTurboModule::InitParams &)params
{
  return std::make_shared<DeceiptTurboModuleJSI>(params, _backend);
}

- (void)invalidate
{
  [_backend invalidate];
}

- (void)dealloc
{
  [[NSNotificationCenter defaultCenter] removeObserver:self];
  [_backend invalidate];
}

@end
