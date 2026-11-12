import XCTest

/// Walks through the app the way a first-time user would and attaches a
/// screenshot of each screen. CI runs it on an iPhone and an iPad simulator
/// (.github/workflows/mobile.yml) and exports the screenshots.
///
/// Sample data uses placeholder names only (docs/user-guide/README.md).
final class TourTests: XCTestCase {
    /// The throwaway vault's master password, made up by ios-ui-test.sh for each run.
    private let phrase = ProcessInfo.processInfo.environment["PHRASE"] ?? UUID().uuidString
    private let device = ProcessInfo.processInfo.environment["DEVICE"] ?? "device"
    private var app: XCUIApplication!
    private var n = 0

    override func setUp() {
        continueAfterFailure = false
        app = XCUIApplication()
    }

    func testTour() {
        // iPads start in landscape, where all three columns show.
        if UIDevice.current.userInterfaceIdiom == .pad { XCUIDevice.shared.orientation = .landscapeLeft }
        app.launch()
        if app.buttons["Create a New Vault"].waitForExistence(timeout: 10) {
            createVault()
        } else {
            unlock("unlock")
        }
        addLogin()
        addCard()
        addCode()
        addSshKey()
        open("Generator")
        XCTAssertTrue(app.buttons["3 Words"].waitForExistence(timeout: 10), "Generator did not open")
        shot("generator")
        app.buttons["3 Words"].tap(); sleep(1); shot("generator-words")
        app.buttons["Apple Style"].tap(); sleep(1); shot("generator-apple")
        open("Settings"); shot("settings")
        settingsPage("Unlock Methods", title: "Unlock Methods", expect: "Change Master Password")
        settingsPage("Import from Another App", title: "Import", expect: "Choose Export File")
        tapScrolling(app.buttons["Lock Now"])
        XCTAssertTrue(app.buttons["Unlock"].waitForExistence(timeout: 10))
        unlock("locked")
        if UIDevice.current.userInterfaceIdiom == .pad {
            XCUIDevice.shared.orientation = .portrait
            sleep(2)
            shot("portrait")
        }
    }

    override func tearDown() {
        if let run = testRun, run.failureCount > 0 { shot("failure") }
    }

    // MARK: Steps

    private func createVault() {
        shot("welcome")
        app.buttons["Create a New Vault"].tap()
        type(phrase, into: app.secureTextFields["Master password"])
        type(phrase, into: app.secureTextFields["Type it again"])
        shot("create")
        app.buttons["Create Vault"].tap()
        XCTAssertTrue(app.staticTexts["Your Recovery Code"].waitForExistence(timeout: 180))
        shot("recovery-code")
        let toggle = app.switches["I wrote it down"]
        if toggle.switches.firstMatch.exists { toggle.switches.firstMatch.tap() } else { toggle.tap() }
        app.buttons["Continue"].tap()
        XCTAssertTrue(newItemButton.waitForExistence(timeout: 120))
        shot("items-empty")
    }

    private func unlock(_ name: String) {
        XCTAssertTrue(app.secureTextFields["Password"].waitForExistence(timeout: 10))
        shot(name)
        type(phrase, into: app.secureTextFields["Password"])
        app.buttons["Unlock"].tap()
        // Unlocking runs Argon2 with 256 MiB; on a slow runner a UI query
        // made meanwhile can time out ("Failed to get matching snapshots"),
        // which fails the test outright. Let the key derivation finish first.
        Thread.sleep(forTimeInterval: 20)
        XCTAssertTrue(newItemButton.waitForExistence(timeout: 420))
    }

    private func addLogin() {
        if app.staticTexts["Example Mail"].exists { return }
        newItem("Login")
        type("Example Mail", into: app.textFields["Title, e.g. Example Mail"])
        type("alex@example.com", into: app.textFields["Username or email"])
        type("mail.example.com", into: app.textFields["example.com"])
        type("GEZDGNBVGY3TQOJQ", into: app.textFields["Setup key or otpauth:// link"])
        shot("new-login")
        save()
        openItem("Example Mail")
        shot("login")
    }

    private func addCard() {
        if app.staticTexts["Everyday Card"].exists { return }
        open("Items")
        newItem("Card")
        type("Everyday Card", into: app.textFields["Title, e.g. Everyday Visa"])
        type("Alex Example", into: app.textFields["Name on card"])
        type("4111111111111111", into: app.textFields["Card number"])
        type("08/29", into: app.textFields["MM/YY"])
        save()
        openItem("Everyday Card")
        shot("card")
        open("Items")
        shot("items")
    }

    /// Adds a code straight from the Codes tab, as a new login.
    private func addCode() {
        open("Codes")
        if !app.staticTexts["Example Chat"].exists {
            app.buttons["Add Code"].firstMatch.tap()
            XCTAssertTrue(app.buttons["Save"].waitForExistence(timeout: 10))
            type("JBSWY3DPEHPK3PXP", into: app.textFields["Setup key or otpauth:// link"])
            type("Example Chat", into: app.textFields["Name, e.g. Example Mail"])
            shot("add-code")
            save()
        }
        XCTAssertTrue(app.staticTexts["Example Chat"].waitForExistence(timeout: 10))
        shot("codes")
    }

    /// New Item › SSH Key, then the key's public half.
    private func addSshKey() {
        open("Items")
        if !app.staticTexts["Example Server"].exists {
            newItemButton.tap()
            app.buttons["SSH Key"].firstMatch.tap()
            XCTAssertTrue(app.buttons["Make Key"].waitForExistence(timeout: 10))
            type("Example Server", into: app.textFields.firstMatch)
            shot("ssh-key-new")
            app.buttons["Make Key"].tap()
            XCTAssertTrue(app.buttons["Make Key"].waitForNonExistence(timeout: 30))
        }
        openItem("Example Server")
        XCTAssertTrue(app.buttons["Copy Public Key"].waitForExistence(timeout: 10))
        shot("ssh-key")
    }

    /// Opens a Settings row that pushes a page, checks it, and goes back.
    private func settingsPage(_ label: String, title: String, expect: String) {
        tapScrolling(app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", label)).firstMatch)
        XCTAssertTrue(app.buttons[expect].waitForExistence(timeout: 10))
        shot(label.lowercased().replacingOccurrences(of: " ", with: "-"))
        // On iPhone the page is pushed over Settings and has a back button.
        // On iPad the split view shows it in the detail column, beside the
        // Settings list, with no back button: the list stays tappable.
        let back = app.navigationBars.buttons.matching(
            NSPredicate(format: "identifier == 'BackButton' OR label == 'Settings' OR label == 'Back'")
        ).firstMatch
        if back.waitForExistence(timeout: 3) {
            back.tap()
            XCTAssertTrue(app.buttons[expect].waitForNonExistence(timeout: 10))
        } else {
            let list = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", label)).firstMatch
            if !list.exists { print(app.debugDescription) }
            XCTAssertTrue(list.exists, "\(title) has no back button and hides the Settings list")
        }
    }

    // MARK: Helpers

    private var newItemButton: XCUIElement { app.buttons["New Item"].firstMatch }

    private func newItem(_ kind: String) {
        newItemButton.tap()
        app.buttons[kind].firstMatch.tap()
        XCTAssertTrue(app.buttons["Save"].waitForExistence(timeout: 10))
    }

    private func save() {
        app.buttons["Save"].tap()
        XCTAssertTrue(app.buttons["Save"].waitForNonExistence(timeout: 30))
    }

    /// Opens an item: pushes it on a phone, selects it in the list on an iPad.
    private func openItem(_ title: String) {
        let row = app.cells.containing(.staticText, identifier: title).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        row.tap()
        sleep(1)
    }

    /// A tab on a phone, a sidebar row on an iPad.
    private func open(_ name: String) {
        let tab = app.tabBars.buttons[name]
        if tab.exists { tab.tap(); sleep(1); return }
        let sidebar: String
        switch name {
        case "Items": sidebar = "All Items"
        default: sidebar = name
        }
        // After an item opens, the iPad can collapse the sidebar: the row is
        // still in the tree but off screen, so tapping it does nothing.
        let row = app.cells.containing(.staticText, identifier: sidebar).firstMatch
        if !(row.exists && row.isHittable), app.buttons["ToggleSidebar"].exists {
            app.buttons["ToggleSidebar"].tap()
            _ = row.waitForExistence(timeout: 5)
            sleep(1)
        }
        row.tap()
        sleep(1)
    }

    private func type(_ text: String, into field: XCUIElement) {
        tapScrolling(field)
        // The simulator may offer a strong password for new-password fields.
        let own = app.buttons["Choose My Own Password"]
        if own.waitForExistence(timeout: 1) { own.tap(); field.tap() }
        // On a slow iPad simulator the tap can land before the field takes
        // the keyboard ("Neither element nor any descendant has keyboard
        // focus"). Tap again until it has focus, then type.
        for _ in 0..<3 where !hasFocus(field) {
            sleep(2)
            field.tap()
        }
        field.typeText(text)
    }

    private func hasFocus(_ field: XCUIElement) -> Bool {
        (field.value(forKey: "hasKeyboardFocus") as? Bool) ?? false
    }

    /// Taps an element, scrolling down to it first. Lists and forms only
    /// create rows near the screen, so a row further down doesn't exist yet.
    private func tapScrolling(_ element: XCUIElement) {
        _ = element.waitForExistence(timeout: 5)
        var tries = 0
        while !(element.exists && element.isHittable) && tries < 8 {
            app.swipeUp()
            tries += 1
        }
        XCTAssertTrue(element.exists, "\(element) is missing")
        element.tap()
    }

    private func shot(_ name: String) {
        n += 1
        let a = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        a.name = String(format: "%@-%02d-%@", device, n, name)
        a.lifetime = .keepAlways
        add(a)
    }
}
