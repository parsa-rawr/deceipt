import XCTest

// DeceiptUITests — an autonomous UI driver so the physical iPhone can be driven
// without hand-tapping. It taps the accessibility labels A3 published and
// prints the observed state (offer, verification sub-states, history, QR
// payload) to stdout, which `xcodebuild test` surfaces in the log.
//
// Inject the QR payload with the scheme/environment variable QR_PAYLOAD (e.g.
// the `deceipt1:` string captured from the Android merchant). The app itself is
// NOT given that variable — only this test process reads it.
final class DeceiptUITests: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    // MARK: - helpers

    private func app() -> XCUIApplication {
        let app = XCUIApplication()
        // Opt this build into test provisioning (the app honours this launch
        // environment variable) so the merchant test can import the PoC test
        // key; a production launch never sets it.
        app.launchEnvironment["DECEIPT_TEST_PROVISIONING"] = "1"
        app.launch()
        return app
    }

    /// Resolves an element by accessibility identifier or label, whichever the
    /// app exposes.
    private func element(_ app: XCUIApplication, _ id: String) -> XCUIElement {
        let byId = app.descendants(matching: .any).matching(identifier: id).firstMatch
        if byId.exists { return byId }
        return app.descendants(matching: .any).matching(NSPredicate(format: "label == %@", id)).firstMatch
    }

    private func waitFor(_ element: XCUIElement, _ timeout: TimeInterval = 30, _ what: String) {
        XCTAssertTrue(element.waitForExistence(timeout: timeout), "\(what) did not appear in \(timeout)s")
    }

    private func tap(_ app: XCUIApplication, _ id: String, _ timeout: TimeInterval = 30) {
        let el = element(app, id)
        waitFor(el, timeout, "\(id)")
        el.tap()
    }

    private func dump(_ app: XCUIApplication, _ id: String) -> String {
        let el = app.descendants(matching: .any).matching(identifier: id).firstMatch
        guard el.exists else { return "<\(id) not present>" }
        var parts: [String] = []
        // The element's own label/value, plus each descendant's label/value, so
        // sub-state rows are visible even when they have no identifier.
        parts.append(el.label)
        if let v = el.value as? String, !v.isEmpty { parts.append("value=\(v)") }
        for child in el.descendants(matching: .any).allElementsBoundByIndex {
            let l = child.label
            if !l.isEmpty { parts.append(l) }
            if let v = child.value as? String, !v.isEmpty, v != l { parts.append(v) }
        }
        return parts.joined(separator: " | ")
    }

    private func dismissPermissionIfNeeded(_ app: XCUIApplication) {
        let warning = element(app, "permission-warning")
        guard warning.waitForExistence(timeout: 3) else { return }
        tap(app, "request-permissions")
        // System permission alert: allow if presented.
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        for label in ["Allow", "OK", "Allow While Using App", "Allow Once"] {
            let button = springboard.buttons[label]
            if button.waitForExistence(timeout: 2) { button.tap(); break }
        }
        // Re-evaluate.
        if element(app, "permission-warning").exists {
            XCTFail("Bluetooth permission still failing after request: \(dump(app, "permission-warning"))")
        }
    }

    // MARK: - CUSTOMER test

    func testCustomerFlowFromQrPayload() throws {
        let payload = ProcessInfo.processInfo.environment["QR_PAYLOAD"] ?? ""
        XCTAssertFalse(payload.isEmpty, "QR_PAYLOAD env var must be set to the deceipt1: payload from the merchant")

        let app = app()
        waitFor(element(app, "app-root"), 120, "app-root")

        // The adapter report lives on the menu; it is replaced once a mode is
        // selected, so assert it before switching modes.
        XCTAssertTrue(element(app, "adapter-compatible").waitForExistence(timeout: 5),
                      "adapter NOT compatible: \(dump(app, "adapter-card"))")

        tap(app, "mode-customer")
        waitFor(element(app, "customer-screen"), 30, "customer-screen")

        dismissPermissionIfNeeded(app)

        let input = app.textFields["qr-payload-input"].exists
            ? app.textFields["qr-payload-input"]
            : app.textViews["qr-payload-input"]
        waitFor(input, 10, "qr-payload-input")
        input.tap()
        input.typeText(payload)

        tap(app, "scan-qr")
        let offer = element(app, "offer-card")
        if !offer.waitForExistence(timeout: 60) {
            let diag = [
                "permission=\(dump(app, "permission-warning"))",
                "checkoutError=\(dump(app, "checkout-error"))",
                "customerLog=\(dump(app, "customer-log-card"))",
                "state=\(dump(app, "checkout-state"))",
            ].joined(separator: " || ")
            XCTFail("offer-card never appeared. \(diag)")
            return
        }
        print("OFFER_CARD: " + dump(app, "offer-card"))

        tap(app, "accept-offer")
        waitFor(element(app, "receipt-result"), 60, "receipt-result")
        print("RECEIPT_RESULT: " + dump(app, "receipt-result"))
        print("RECEIPT_STATUS: " + dump(app, "receipt-status-text"))
        print("VERIFICATION_PILL: " + dump(app, "receipt-verification-pill"))
        print("HISTORY_ROW_0: " + dump(app, "history-row-0"))

        let status = dump(app, "receipt-status-text")
        XCTAssertTrue(status.contains("Verified"), "receipt-status-text did not contain 'Verified': \(status)")
    }

    // MARK: - MERCHANT test

    func testMerchantPrintsQrPayload() throws {
        let app = app()
        waitFor(element(app, "app-root"), 120, "app-root")

        XCTAssertTrue(element(app, "adapter-compatible").waitForExistence(timeout: 5),
                      "adapter NOT compatible: \(dump(app, "adapter-card"))")

        tap(app, "mode-merchant")
        waitFor(element(app, "merchant-screen"), 30, "merchant-screen")

        if element(app, "merchant-key-missing").waitForExistence(timeout: 3) {
            tap(app, "provision-test-merchant")
            _ = element(app, "merchant-device-key-id").waitForExistence(timeout: 10)
        }

        dismissPermissionIfNeeded(app)
        tap(app, "prepare-checkout")

        let qr = element(app, "qr-payload-text")
        if !qr.waitForExistence(timeout: 25) {
            let diag = [
                "phase=\(dump(app, "merchant-phase"))",
                "keyMissing=\(element(app, "merchant-key-missing").exists)",
                "provisionNote=\(dump(app, "provision-note"))",
                "merchantError=\(dump(app, "merchant-error"))",
                "keyId=\(dump(app, "merchant-device-key-id"))",
            ].joined(separator: " || ")
            XCTFail("prepare-checkout produced no QR payload. \(diag)")
            return
        }
        // Selectable Text exposes its content as `value`; concatenate with label.
        var printed = qr.label
        if let v = qr.value as? String, !v.isEmpty { printed = v }
        print("QR_PAYLOAD_BEGIN")
        print(printed)
        print("QR_PAYLOAD_END")
        XCTAssertTrue(printed.hasPrefix("deceipt1:"), "qr-payload-text did not expose a deceipt1: payload: \(printed)")
    }
}
