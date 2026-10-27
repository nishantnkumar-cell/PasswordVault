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
        open("Codes"); shot("codes")
        open("Generator"); shot("generator")
        open("Settings"); shot("settings")
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
        XCTAssertTrue(newItemButton.waitForExistence(timeout: 30))
        shot("items-empty")
    }

    private func unlock(_ name: String) {
        XCTAssertTrue(app.secureTextFields["Password"].waitForExistence(timeout: 10))
        shot(name)
        type(phrase, into: app.secureTextFields["Password"])
        app.buttons["Unlock"].tap()
        XCTAssertTrue(newItemButton.waitForExistence(timeout: 180))
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
        case "Codes": sidebar = "One-Time Codes"
        default: sidebar = name
        }
        let row = app.cells.containing(.staticText, identifier: sidebar).firstMatch
        if !row.exists, app.buttons["ToggleSidebar"].exists { app.buttons["ToggleSidebar"].tap() }
        row.tap()
        sleep(1)
    }

    private func type(_ text: String, into field: XCUIElement) {
        tapScrolling(field)
        // The simulator may offer a strong password for new-password fields.
        let own = app.buttons["Choose My Own Password"]
        if own.waitForExistence(timeout: 1) { own.tap(); field.tap() }
        field.typeText(text)
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
