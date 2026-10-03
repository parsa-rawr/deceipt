package com.deceipt.adapter.ble

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

/**
 * Runtime permission matrix, status probe and Bluetooth capability report (A5).
 *
 * Matrix (minSdk 24, targetSdk 36):
 *  * API 31+ (S): `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT`, `BLUETOOTH_SCAN` are
 *    requestable (neverForLocation is declared on SCAN in the manifest).
 *  * API 24..30: `BLUETOOTH` + `BLUETOOTH_ADMIN` (install-time, always granted
 *    post-install) plus `ACCESS_FINE_LOCATION` for scanning.
 *  * Camera: `CAMERA` (QR acquisition, all API levels with a camera).
 *
 * This object never prompts. It only observes. Requesting is the module layer's
 * job; a missing grant is reported, and every platform class throws
 * `TRANSPORT_PERMISSION_DENIED` before touching an adapter API.
 */
object BlePermissions {

    const val API_S = Build.VERSION_CODES.S

    /** The role a permission requirement is evaluated for. */
    enum class Role { MERCHANT, CUSTOMER }

    /** Bluetooth radio state, matching the shared `BluetoothState` union. */
    enum class State(val wire: String) {
        ON("on"),
        OFF("off"),
        UNSUPPORTED("unsupported"),
        UNAUTHORIZED("unauthorized"),
        UNKNOWN("unknown"),
    }

    /** Platform permission status, matching the shared `PermissionStatus` union. */
    enum class Status(val wire: String) {
        GRANTED("granted"),
        DENIED("denied"),
        RESTRICTED("restricted"),
        UNDETERMINED("undetermined"),
        UNAVAILABLE("unavailable"),
    }

    /**
     * The report the module forwards to the shared UI. `cameraGranted` is
     * `null` when the device has no camera feature at all.
     */
    data class PermissionReport(
        val bluetoothGranted: Boolean,
        val advertisingGranted: Boolean,
        val scanGranted: Boolean,
        val cameraGranted: Boolean?,
        val bluetoothState: String,
        val apiLevel: Int,
        val bluetoothStatus: Status = Status.UNDETERMINED,
        val cameraStatus: Status = Status.UNAVAILABLE,
        val advertisingStatus: Status = Status.UNDETERMINED,
        val scanStatus: Status = Status.UNDETERMINED,
        val bluetoothSupported: Boolean = bluetoothState != State.UNSUPPORTED.wire,
    ) {
        val state: State
            get() = State.entries.firstOrNull { it.wire == bluetoothState } ?: State.UNKNOWN

        /** `true` when the given role can drive the radio at all. */
        fun isRoleReady(role: Role): Boolean = when (role) {
            Role.MERCHANT -> bluetoothGranted && advertisingGranted && bluetoothState == State.ON.wire
            Role.CUSTOMER -> bluetoothGranted && scanGranted && bluetoothState == State.ON.wire
        }
    }

    // -----------------------------------------------------------------------
    // Required permissions
    // -----------------------------------------------------------------------

    /**
     * The permissions the given role needs on this device. Empty elements are
     * never returned; the list may legitimately be empty (API 24..30 merchant,
     * where BLUETOOTH/BLUETOOTH_ADMIN are install-time only).
     */
    fun requiredPermissions(role: Role, apiLevel: Int = Build.VERSION.SDK_INT): List<String> =
        when {
            apiLevel >= API_S -> when (role) {
                Role.MERCHANT -> listOf(Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)
                Role.CUSTOMER -> listOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
            }

            else -> when (role) {
                // Legacy scanning is gated on location; advertising needs nothing runtime.
                Role.MERCHANT -> emptyList()
                Role.CUSTOMER -> listOf(Manifest.permission.ACCESS_FINE_LOCATION)
            }
        }

    /** Permissions to request in one prompt for `role`, camera included on request. */
    fun requestablePermissions(role: Role, includeCamera: Boolean = false, apiLevel: Int = Build.VERSION.SDK_INT): List<String> {
        val base = requiredPermissions(role, apiLevel).toMutableList()
        if (includeCamera) base.add(Manifest.permission.CAMERA)
        return base
    }

    /** The camera permission used for QR acquisition (never a BLE requirement). */
    fun cameraPermission(): String = Manifest.permission.CAMERA

    /** Bluetooth permissions that exist on this API level (legacy or S+). */
    fun bluetoothPermissions(apiLevel: Int = Build.VERSION.SDK_INT): List<String> = if (apiLevel >= API_S) {
        listOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)
    } else {
        listOf(Manifest.permission.BLUETOOTH, Manifest.permission.BLUETOOTH_ADMIN, Manifest.permission.ACCESS_FINE_LOCATION)
    }

    // -----------------------------------------------------------------------
    // Probing
    // -----------------------------------------------------------------------

    /** `true` when every permission the role needs is granted. Never prompts. */
    fun allGranted(context: Context, role: Role): Boolean =
        requiredPermissions(role).all { granted(context, it) }

    fun granted(context: Context, permission: String): Boolean =
        context.checkPermission(permission, android.os.Process.myPid(), android.os.Process.myUid()) ==
            PackageManager.PERMISSION_GRANTED

    /** Per-permission status; `UNAVAILABLE` when the permission is not declared. */
    fun status(context: Context, permission: String): Status = try {
        when {
            granted(context, permission) -> Status.GRANTED
            !declared(context, permission) -> Status.UNAVAILABLE
            else -> Status.DENIED
        }
    } catch (t: Throwable) {
        Status.UNDETERMINED
    }

    fun cameraStatus(context: Context): Status =
        if (!hasCamera(context)) Status.UNAVAILABLE else status(context, Manifest.permission.CAMERA)

    fun hasCamera(context: Context): Boolean =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)

    /** `BluetoothAdapter != null && adapter.isEnabled`. Adapter null => unsupported. */
    fun isAvailable(context: Context): Boolean {
        val adapter = adapter(context) ?: return false
        return try {
            adapter.isEnabled
        } catch (se: SecurityException) {
            false
        }
    }

    /** The system adapter, or null when the device has no Bluetooth hardware. */
    fun adapter(context: Context): BluetoothAdapter? = try {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        manager?.adapter
    } catch (t: Throwable) {
        null
    }

    /**
     * Observe the radio state. API 31+ requires BLUETOOTH_CONNECT to read it, so
     * a missing grant reports `unauthorized` rather than `unknown`.
     */
    fun bluetoothState(context: Context): State {
        val adapter = adapter(context) ?: return State.UNSUPPORTED
        return try {
            when (adapter.state) {
                BluetoothAdapter.STATE_ON -> State.ON
                BluetoothAdapter.STATE_TURNING_ON -> State.ON
                BluetoothAdapter.STATE_OFF, BluetoothAdapter.STATE_TURNING_OFF -> State.OFF
                else -> State.UNKNOWN
            }
        } catch (se: SecurityException) {
            State.UNAUTHORIZED
        }
    }

    /** The full report. Never throws; never prompts. */
    fun report(context: Context): PermissionReport {
        val apiLevel = Build.VERSION.SDK_INT
        val adapter = adapter(context)
        val connectPermission = if (apiLevel >= API_S) Manifest.permission.BLUETOOTH_CONNECT else Manifest.permission.BLUETOOTH
        val connectStatus = if (adapter == null) Status.UNAVAILABLE else status(context, connectPermission)
        val state = when {
            adapter == null -> State.UNSUPPORTED
            apiLevel >= API_S && connectStatus != Status.GRANTED -> State.UNAUTHORIZED
            else -> bluetoothState(context)
        }
        val advertisingStatus = if (adapter == null || apiLevel < API_S) {
            if (adapter == null) Status.UNAVAILABLE else Status.GRANTED
        } else {
            status(context, Manifest.permission.BLUETOOTH_ADVERTISE)
        }
        val scanStatus = when {
            adapter == null -> Status.UNAVAILABLE
            apiLevel >= API_S -> status(context, Manifest.permission.BLUETOOTH_SCAN)
            else -> status(context, Manifest.permission.ACCESS_FINE_LOCATION)
        }
        val bluetoothGranted = adapter != null &&
            connectStatus == Status.GRANTED &&
            (apiLevel >= API_S || granted(context, Manifest.permission.BLUETOOTH))
        val camera = cameraStatus(context)
        return PermissionReport(
            bluetoothGranted = bluetoothGranted,
            advertisingGranted = adapter != null && advertisingStatus == Status.GRANTED,
            scanGranted = adapter != null && scanStatus == Status.GRANTED,
            cameraGranted = if (camera == Status.UNAVAILABLE) null else camera == Status.GRANTED,
            bluetoothState = state.wire,
            apiLevel = apiLevel,
            bluetoothStatus = connectStatus,
            cameraStatus = camera,
            advertisingStatus = advertisingStatus,
            scanStatus = scanStatus,
            bluetoothSupported = adapter != null,
        )
    }

    /**
     * The frozen error to raise before touching an adapter API, or null when the
     * role may proceed. Order matters: radio first, then permission.
     */
    fun preconditionFailure(context: Context, role: Role): String? {
        val report = report(context)
        return when {
            !report.bluetoothSupported -> "CAPABILITY_UNAVAILABLE"
            report.bluetoothState == State.OFF.wire -> "TRANSPORT_BLUETOOTH_OFF"
            report.bluetoothState == State.UNAUTHORIZED.wire -> "TRANSPORT_PERMISSION_DENIED"
            !report.isRoleReady(role) -> "TRANSPORT_PERMISSION_DENIED"
            else -> null
        }
    }

    private fun declared(context: Context, permission: String): Boolean = try {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        val requested = info.requestedPermissions ?: emptyArray()
        requested.any { it == permission }
    } catch (t: Throwable) {
        false
    }
}
