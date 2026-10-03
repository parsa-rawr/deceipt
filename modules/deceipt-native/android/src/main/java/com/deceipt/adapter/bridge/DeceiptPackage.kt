package com.deceipt.adapter.bridge

import com.deceipt.adapter.ble.GattUuids
import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager

/**
 * Registers the single legacy module `DeceiptNative`
 * (modules/deceipt-native/index.ts `NATIVE_MODULE_NAME`). No codegen spec: the
 * frozen TypeScript contract `app/src/native/DeceiptNative.ts` is the single
 * source of truth for both platforms.
 */
class DeceiptPackage : ReactPackage {
    override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> =
        listOf(DeceiptNativeModule(reactContext))

    override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>> =
        emptyList()

    companion object {
        const val MODULE_NAME = "DeceiptNative"

        /** Canonical lower-case form of the frozen service UUID. */
        val GATT_SERVICE = GattUuids.canonical(GattUuids.SERVICE)
    }
}
