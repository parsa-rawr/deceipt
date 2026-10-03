package com.deceipt.adapter.ble

import java.util.UUID

/**
 * Frozen GATT identifiers (wire.md 1, A1 pass D). Changing any value here is a
 * protocol revision break.
 *
 * | Role | UUID |
 * |---|---|
 * | Deceipt Transfer Service | `8decc0de-1e57-4000-8000-000000000001` |
 * | COMMAND (B->A) | `8decc0de-1e57-4000-8000-000000000002` — write with response |
 * | EVENT (A->B) | `8decc0de-1e57-4000-8000-000000000003` — indicate |
 * | DATA (A->B) | `8decc0de-1e57-4000-8000-000000000004` — notify |
 *
 * Peripheral = merchant (GATT server); central = customer (GATT client). The
 * advertisement carries the service UUID and nothing else.
 */
object GattUuids {

    val SERVICE: UUID = UUID.fromString("8decc0de-1e57-4000-8000-000000000001")
    val COMMAND: UUID = UUID.fromString("8decc0de-1e57-4000-8000-000000000002")
    val EVENT: UUID = UUID.fromString("8decc0de-1e57-4000-8000-000000000003")
    val DATA: UUID = UUID.fromString("8decc0de-1e57-4000-8000-000000000004")

    /** Client Characteristic Configuration descriptor (subscribe/unsubscribe). */
    val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    val ALL: List<UUID> = listOf(SERVICE, COMMAND, EVENT, DATA)

    fun isService(uuid: UUID): Boolean = SERVICE == uuid

    fun isCommand(uuid: UUID): Boolean = COMMAND == uuid

    fun isEvent(uuid: UUID): Boolean = EVENT == uuid

    fun isData(uuid: UUID): Boolean = DATA == uuid

    /** `true` for the COMMAND/EVENT/DATA characteristics (not the service). */
    fun isCharacteristic(uuid: UUID): Boolean = isCommand(uuid) || isEvent(uuid) || isData(uuid)

    fun isCccd(uuid: UUID): Boolean = CCCD == uuid

    /** Canonical lower-case form, for logs and diagnostics. */
    fun canonical(uuid: UUID): String = uuid.toString().lowercase()
}
