import AppKit
import MCP
import Network
import OSLog
import Ontology
import SwiftUI
import SystemPackage
import UserNotifications

import struct Foundation.Data
import struct Foundation.Date
import class Foundation.JSONDecoder
import class Foundation.JSONEncoder

private let serviceType = "_mcp._tcp"
private let serviceDomain = "local."

private let log = Logger.server

struct ServiceConfig: Identifiable {
    let id: String
    let name: String
    let iconName: String
    let color: Color
    let service: any Service
    let binding: Binding<Bool>

    var isActivated: Bool {
        get async {
            await service.isActivated
        }
    }

    init(
        name: String,
        iconName: String,
        color: Color,
        service: any Service,
        binding: Binding<Bool>
    ) {
        self.id = String(describing: type(of: service))
        self.name = name
        self.iconName = iconName
        self.color = color
        self.service = service
        self.binding = binding
    }
}

enum ServiceRegistry {
    static let services: [any Service] = {
        var services: [any Service] = [
            CalendarService.shared,
            CaptureService.shared,
            ContactsService.shared,
            FilesService.shared,
            LocationService.shared,
            MailService.shared,
            MapsService.shared,
            MessageService.shared,
            RemindersService.shared,
            ShortcutsService.shared,
            UtilitiesService.shared,
        ]
        #if WEATHERKIT_AVAILABLE
            services.append(WeatherService.shared)
        #endif
        return services
    }()

    static func configureServices(
        calendarEnabled: Binding<Bool>,
        captureEnabled: Binding<Bool>,
        contactsEnabled: Binding<Bool>,
        filesEnabled: Binding<Bool>,
        locationEnabled: Binding<Bool>,
        mailEnabled: Binding<Bool>,
        mapsEnabled: Binding<Bool>,
        messagesEnabled: Binding<Bool>,
        remindersEnabled: Binding<Bool>,
        shortcutsEnabled: Binding<Bool>,
        utilitiesEnabled: Binding<Bool>,
        weatherEnabled: Binding<Bool>
    ) -> [ServiceConfig] {
        var configs: [ServiceConfig] = [
            ServiceConfig(
                name: "Calendar",
                iconName: "calendar",
                color: .red,
                service: CalendarService.shared,
                binding: calendarEnabled
            ),
            ServiceConfig(
                name: "Capture",
                iconName: "camera.on.rectangle.fill",
                color: .gray.mix(with: .black, by: 0.7),
                service: CaptureService.shared,
                binding: captureEnabled
            ),
            ServiceConfig(
                name: "Contacts",
                iconName: "person.crop.square.filled.and.at.rectangle.fill",
                color: .brown,
                service: ContactsService.shared,
                binding: contactsEnabled
            ),
            ServiceConfig(
                name: "Files",
                iconName: "folder.fill",
                color: .teal,
                service: FilesService.shared,
                binding: filesEnabled
            ),
            ServiceConfig(
                name: "Location",
                iconName: "location.fill",
                color: .blue,
                service: LocationService.shared,
                binding: locationEnabled
            ),
            ServiceConfig(
                name: "Mail",
                iconName: "envelope.fill",
                color: .blue,
                service: MailService.shared,
                binding: mailEnabled
            ),
            ServiceConfig(
                name: "Maps",
                iconName: "mappin.and.ellipse",
                color: .purple,
                service: MapsService.shared,
                binding: mapsEnabled
            ),
            ServiceConfig(
                name: "Messages",
                iconName: "message.fill",
                color: .green,
                service: MessageService.shared,
                binding: messagesEnabled
            ),
            ServiceConfig(
                name: "Reminders",
                iconName: "list.bullet",
                color: .orange,
                service: RemindersService.shared,
                binding: remindersEnabled
            ),
            ServiceConfig(
                name: "Shortcuts",
                iconName: "square.2.layers.3d",
                color: .indigo,
                service: ShortcutsService.shared,
                binding: shortcutsEnabled
            ),
            ServiceConfig(
                name: "Utilities",
                iconName: "wrench.and.screwdriver.fill",
                color: .gray,
                service: UtilitiesService.shared,
                binding: utilitiesEnabled
            ),
        ]
        #if WEATHERKIT_AVAILABLE
            configs.append(
                ServiceConfig(
                    name: "Weather",
                    iconName: "cloud.sun.fill",
                    color: .cyan,
                    service: WeatherService.shared,
                    binding: weatherEnabled
                )
            )
        #endif
        return configs
    }
}

@MainActor
final class ServerController: ObservableObject {
    @Published var serverStatus: String = "Starting..."
    @Published var pendingConnectionID: String?
    @Published var pendingClientName: String = ""

    private var activeApprovalDialogs: Set<String> = []
    private var pendingApprovals: [(String, () -> Void, () -> Void)] = []
    private var currentApprovalHandlers: (approve: () -> Void, deny: () -> Void)?
    private let approvalWindowController = ConnectionApprovalWindowController()

    private let networkManager = ServerNetworkManager()

    // MARK: - AppStorage for Service Enablement States
    @AppStorage("calendarEnabled") private var calendarEnabled = false
    @AppStorage("captureEnabled") private var captureEnabled = false
    @AppStorage("contactsEnabled") private var contactsEnabled = false
    @AppStorage("filesEnabled") private var filesEnabled = false
    @AppStorage("locationEnabled") private var locationEnabled = false
    @AppStorage("mailEnabled") private var mailEnabled = false
    @AppStorage("mapsEnabled") private var mapsEnabled = false
    @AppStorage("messagesEnabled") private var messagesEnabled = false
    @AppStorage("remindersEnabled") private var remindersEnabled = false
    @AppStorage("shortcutsEnabled") private var shortcutsEnabled = false
    @AppStorage("utilitiesEnabled") private var utilitiesEnabled = false
    @AppStorage("weatherEnabled") private var weatherEnabled = false

    // MARK: - AppStorage for Trusted Clients
    @AppStorage("trustedClients") private var trustedClientsData = Data()

    // MARK: - Computed Properties for Service Configurations and Bindings
    var computedServiceConfigs: [ServiceConfig] {
        ServiceRegistry.configureServices(
            calendarEnabled: $calendarEnabled,
            captureEnabled: $captureEnabled,
            contactsEnabled: $contactsEnabled,
            filesEnabled: $filesEnabled,
            locationEnabled: $locationEnabled,
            mailEnabled: $mailEnabled,
            mapsEnabled: $mapsEnabled,
            messagesEnabled: $messagesEnabled,
            remindersEnabled: $remindersEnabled,
            shortcutsEnabled: $shortcutsEnabled,
            utilitiesEnabled: $utilitiesEnabled,
            weatherEnabled: $weatherEnabled
        )
    }

    // MARK: - Trusted Clients Management
    private var trustedClients: Set<String> {
        get {
            (try? JSONDecoder().decode(Set<String>.self, from: trustedClientsData)) ?? []
        }
        set {
            trustedClientsData = (try? JSONEncoder().encode(newValue)) ?? Data()
        }
    }

    private func isClientTrusted(_ clientName: String) -> Bool {
        trustedClients.contains(clientName)
    }

    private func addTrustedClient(_ clientName: String) {
        var clients = trustedClients
        clients.insert(clientName)
        trustedClients = clients
    }

    func removeTrustedClient(_ clientName: String) {
        var clients = trustedClients
        clients.remove(clientName)
        trustedClients = clients
    }

    func getTrustedClients() -> [String] {
        Array(trustedClients).sorted()
    }

    func resetTrustedClients() {
        trustedClients = Set<String>()
    }

    // MARK: - Connection Approval Methods
    private func cleanupApprovalState() {
        pendingClientName = ""
        currentApprovalHandlers = nil

        if let clientID = pendingConnectionID {
            activeApprovalDialogs.remove(clientID)
            pendingConnectionID = nil
        }
    }

    private func handlePendingApprovals(for clientID: String, approved: Bool) {
        while let pendingIndex = pendingApprovals.firstIndex(where: { $0.0 == clientID }) {
            let (_, pendingApprove, pendingDeny) = pendingApprovals.remove(at: pendingIndex)
            if approved {
                log.notice("Approving pending connection for client: \(clientID)")
                pendingApprove()
            } else {
                log.notice("Denying pending connection for client: \(clientID)")
                pendingDeny()
            }
        }
    }

    init() {
        Task {
            await self.networkManager.start()
            self.updateServerStatus("Running")

            await networkManager.setConnectionApprovalHandler {
                [weak self] connectionID, clientInfo in
                guard let self = self else {
                    return false
                }

                log.debug("ServerManager: Approval handler called for client \(clientInfo.name)")

                // Bridge approval UI actions back into the async handler.
                return await withCheckedContinuation { continuation in
                    let resumeGate = ResumeGate()
                    let resumeOnce: (Bool) async -> Void = { value in
                        guard await resumeGate.shouldResume() else { return }
                        continuation.resume(returning: value)
                    }

                    Task { @MainActor in
                        self.showConnectionApprovalAlert(
                            clientID: clientInfo.name,
                            approve: {
                                Task { await resumeOnce(true) }
                            },
                            deny: {
                                Task { await resumeOnce(false) }
                            }
                        )
                    }
                }
            }
        }
    }

    func updateServiceBindings(_ bindings: [String: Binding<Bool>]) async {
        // Called by the UI when service toggles change. Bindings are written
        // through @AppStorage to UserDefaults; the network manager reads
        // UserDefaults directly, so we just notify connected clients.
        await networkManager.notifyServiceBindingsChanged()
    }

    func startServer() async {
        await networkManager.start()
        updateServerStatus("Running")
    }

    func stopServer() async {
        await networkManager.stop()
        updateServerStatus("Stopped")
    }

    func setEnabled(_ enabled: Bool) async {
        await networkManager.setEnabled(enabled)
        updateServerStatus(enabled ? "Running" : "Disabled")
    }

    private func updateServerStatus(_ status: String) {
        log.info("Server status updated: \(status)")
        self.serverStatus = status
    }

    private func sendClientConnectionNotification(clientName: String) {
        let content = UNMutableNotificationContent()
        content.title = "Client Connected"
        content.body = "Client '\(clientName)' has connected to iMCP-MY"
        content.threadIdentifier = "client-connection-\(clientName)"

        let request = UNNotificationRequest(
            identifier: "client-connection-\(clientName)-\(Date().timeIntervalSince1970)",
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                log.error("Failed to send notification: \(error.localizedDescription)")
            } else {
                log.info("Sent notification for client connection: \(clientName)")
            }
        }
    }

    private func showConnectionApprovalAlert(
        clientID: String,
        approve: @escaping () -> Void,
        deny: @escaping () -> Void
    ) {
        log.notice("Connection approval requested for client: \(clientID)")

        // Trusted clients auto-approve without showing the dialog.
        if isClientTrusted(clientID) {
            log.notice("Client \(clientID) is already trusted, auto-approving")
            approve()

            // Notify the user on auto-approved connections.
            sendClientConnectionNotification(clientName: clientID)

            return
        }

        self.pendingConnectionID = clientID

        // Coalesce concurrent approvals for the same client.
        guard !activeApprovalDialogs.contains(clientID) else {
            log.info("Adding to pending approvals for client: \(clientID)")
            pendingApprovals.append((clientID, approve, deny))
            return
        }

        activeApprovalDialogs.insert(clientID)

        // Present the approval window and wire callbacks.
        pendingClientName = clientID
        currentApprovalHandlers = (approve: approve, deny: deny)

        approvalWindowController.showApprovalWindow(
            clientName: clientID,
            onApprove: { alwaysTrust in
                if alwaysTrust {
                    self.addTrustedClient(clientID)

                    // Ask for notification permission to alert on future trusted connections.
                    UNUserNotificationCenter.current().requestAuthorization(options: [
                        .alert, .sound, .badge,
                    ]) { granted, error in
                        if let error = error {
                            log.error(
                                "Failed to request notification permissions: \(error.localizedDescription)"
                            )
                        } else {
                            log.info("Notification permissions granted: \(granted)")
                        }
                    }
                }

                approve()
                self.cleanupApprovalState()
                self.handlePendingApprovals(for: clientID, approved: true)
            },
            onDeny: {
                deny()
                self.cleanupApprovalState()
                self.handlePendingApprovals(for: clientID, approved: false)
            }
        )

        NSApp.activate(ignoringOtherApps: true)
    }
}

// MARK: - Connection Management Components

// Manages a single MCP connection.
actor MCPConnectionManager {
    private let connectionID: UUID
    private let connection: NWConnection
    private let server: MCP.Server
    private var transport: NetworkTransport
    private let parentManager: ServerNetworkManager

    init(connectionID: UUID, connection: NWConnection, parentManager: ServerNetworkManager) {
        self.connectionID = connectionID
        self.connection = connection
        self.parentManager = parentManager

        // Disable reconnection: server-side NWConnections that are cancelled
        // cannot be restarted (calling `start(queue:)` twice on the same
        // NWConnection triggers `nw_connection_set_queue called after
        // nw_connection_start` and a CheckedContinuation double-resume — see
        // mattt/iMCP#158). The NWListener will vend a fresh NWConnection for
        // any new client, so retrying here is unnecessary.
        self.transport = NetworkTransport(
            connection: connection,
            logger: nil,
            reconnectionConfig: .disabled,
            bufferConfig: .unlimited
        )

        // MCP server instance for this connection.
        self.server = MCP.Server(
            name: Bundle.main.name ?? "iMCP-MY",
            version: Bundle.main.shortVersionString ?? "unknown",
            capabilities: MCP.Server.Capabilities(
                resources: .init(subscribe: true, listChanged: true),
                tools: .init(listChanged: true)
            )
        )
    }

    func notifyResourceUpdated(uri: String) async {
        do {
            try await server.notify(
                ResourceUpdatedNotification.message(.init(uri: uri))
            )
        } catch {
            log.error("Failed to notify resource updated \(uri): \(error.localizedDescription)")
            if let nwError = error as? NWError,
                nwError.errorCode == 57 || nwError.errorCode == 54
            {
                await parentManager.removeConnection(connectionID)
            }
        }
    }

    func start(approvalHandler: @escaping (MCP.Client.Info) async -> Bool) async throws {
        do {
            log.notice("Starting MCP server for connection: \(self.connectionID)")
            try await server.start(transport: transport) { [weak self] clientInfo, capabilities in
                guard let self = self else { throw MCPError.connectionClosed }

                log.info("Received initialize request from client: \(clientInfo.name)")

                // Request user approval for the connection.
                let approved = await approvalHandler(clientInfo)
                log.info(
                    "Approval result for connection \(connectionID): \(approved ? "Approved" : "Denied")"
                )

                if !approved {
                    await self.parentManager.removeConnection(self.connectionID)
                    throw MCPError.connectionClosed
                }
            }

            log.notice("MCP Server started successfully for connection: \(self.connectionID)")

            // Register handlers after successful approval.
            await registerHandlers()

            // Monitor connection health for early disconnects.
            await startHealthMonitoring()
        } catch {
            log.error("Failed to start MCP server: \(error.localizedDescription)")
            throw error
        }
    }

    private func registerHandlers() async {
        await parentManager.registerHandlers(for: server, connectionID: connectionID)
    }

    private func startHealthMonitoring() async {
        // React immediately to state transitions instead of polling every 30s.
        // NetworkTransport clears its own stateUpdateHandler after the initial
        // .ready transition, so installing ours here is safe. Also poll at 1s
        // as a fallback because peer-initiated TCP close may not trigger a
        // state transition on our side unless we call connection.cancel().
        let connectionID = self.connectionID
        let parentManager = self.parentManager
        let connection = self.connection
        connection.stateUpdateHandler = { state in
            switch state {
            case .cancelled:
                log.info("Connection \(connectionID) was cancelled, removing")
                Task { await parentManager.removeConnection(connectionID) }
            case .failed(let error):
                log.error("Connection \(connectionID) failed with error \(error), removing")
                Task { await parentManager.removeConnection(connectionID) }
            default:
                break
            }
        }

        Task {
            outer: while await parentManager.isRunning() {
                try? await Task.sleep(nanoseconds: 1_000_000_000)  // 1 second
                switch connection.state {
                case .ready, .setup, .preparing, .waiting:
                    break
                case .cancelled, .failed:
                    await parentManager.removeConnection(connectionID)
                    break outer
                @unknown default:
                    break
                }
            }
        }
    }

    func notifyToolListChanged() async {
        do {
            log.info("Notifying client that tool list changed")
            try await server.notify(ToolListChangedNotification.message())
        } catch {
            log.error("Failed to notify client of tool list change: \(error)")

            // Clean up if the underlying NWConnection is closed.
            if let nwError = error as? NWError,
                nwError.errorCode == 57 || nwError.errorCode == 54
            {
                log.debug("Connection appears to be closed")
                await parentManager.removeConnection(connectionID)
            }
        }
    }

    func stop() async {
        await server.stop()
        connection.cancel()
    }
}

// Manages Bonjour service discovery and advertisement.
actor NetworkDiscoveryManager {
    private let serviceType: String
    private let serviceDomain: String
    var listener: NWListener
    private let browser: NWBrowser

    init(serviceType: String, serviceDomain: String) throws {
        self.serviceType = serviceType
        self.serviceDomain = serviceDomain

        // Local-only Bonjour advertisement.
        let parameters = NWParameters.tcp
        parameters.acceptLocalOnly = true
        parameters.includePeerToPeer = false

        if let tcpOptions = parameters.defaultProtocolStack.internetProtocol
            as? NWProtocolIP.Options
        {
            tcpOptions.version = .v4
        }

        // Listen and advertise via Bonjour.
        self.listener = try NWListener(using: parameters)
        self.listener.service = NWListener.Service(type: serviceType, domain: serviceDomain)

        // Browser is used for monitoring and diagnostics.
        self.browser = NWBrowser(
            for: .bonjour(type: serviceType, domain: serviceDomain),
            using: parameters
        )

        log.info("Network discovery manager initialized with Bonjour service type: \(serviceType)")
    }

    func start(
        stateHandler: @escaping @Sendable (NWListener.State) -> Void,
        connectionHandler: @escaping @Sendable (NWConnection) -> Void
    ) {
        listener.stateUpdateHandler = stateHandler

        listener.newConnectionHandler = connectionHandler

        listener.start(queue: .main)
        browser.start(queue: .main)

        log.info("Started network discovery and advertisement")
    }

    func stop() {
        listener.cancel()
        browser.cancel()
        log.info("Stopped network discovery and advertisement")
    }

    func restartWithRandomPort() async throws {
        listener.cancel()

        // Recreate listener on an ephemeral port.
        let parameters: NWParameters = NWParameters.tcp  // Explicit type
        parameters.acceptLocalOnly = true
        parameters.includePeerToPeer = false

        if let tcpOptions = parameters.defaultProtocolStack.internetProtocol
            as? NWProtocolIP.Options
        {
            tcpOptions.version = .v4
        }

        let newListener: NWListener = try NWListener(using: parameters)
        let service = NWListener.Service(type: self.serviceType, domain: self.serviceDomain)
        newListener.service = service

        if let currentStateHandler = listener.stateUpdateHandler {
            newListener.stateUpdateHandler = currentStateHandler
        }

        if let currentConnectionHandler = listener.newConnectionHandler {
            newListener.newConnectionHandler = currentConnectionHandler
        }

        newListener.start(queue: .main)

        self.listener = newListener

        log.notice("Restarted listener with a dynamic port")
    }
}

actor ServerNetworkManager {
    private var isRunningState: Bool = false
    private var isEnabledState: Bool = true
    private var discoveryManager: NetworkDiscoveryManager?
    private var connections: [UUID: MCPConnectionManager] = [:]
    private var connectionTasks: [UUID: Task<Void, Never>] = [:]
    private var pendingConnections: [UUID: String] = [:]
    private var resourceSubscriptions: [UUID: [String: ResourceSubscriptionToken]] = [:]

    typealias ConnectionApprovalHandler = @Sendable (UUID, MCP.Client.Info) async -> Bool
    private var connectionApprovalHandler: ConnectionApprovalHandler?

    private let services = ServiceRegistry.services

    // Service-enablement is persisted in UserDefaults by the UI's @AppStorage.
    // We read it directly here because @AppStorage-backed Bindings only stay
    // live inside a SwiftUI view hierarchy — reading wrappedValue from this
    // actor returned stale code-declared defaults.
    private static let serviceDefaults: [(serviceId: String, key: String, defaultEnabled: Bool)] = [
        ("CalendarService", "calendarEnabled", false),
        ("CaptureService", "captureEnabled", false),
        ("ContactsService", "contactsEnabled", false),
        ("FilesService", "filesEnabled", false),
        ("LocationService", "locationEnabled", false),
        ("MailService", "mailEnabled", false),
        ("MapsService", "mapsEnabled", false),
        ("MessageService", "messagesEnabled", false),
        ("RemindersService", "remindersEnabled", false),
        ("ShortcutsService", "shortcutsEnabled", false),
        ("UtilitiesService", "utilitiesEnabled", false),
        ("WeatherService", "weatherEnabled", false),
    ]

    private func isServiceEnabled(_ serviceId: String) -> Bool {
        guard let entry = Self.serviceDefaults.first(where: { $0.serviceId == serviceId }) else {
            return false
        }
        return UserDefaults.standard.object(forKey: entry.key) as? Bool ?? entry.defaultEnabled
    }

    init() {
        do {
            self.discoveryManager = try NetworkDiscoveryManager(
                serviceType: serviceType,
                serviceDomain: serviceDomain
            )
        } catch {
            log.error("Failed to initialize network discovery manager: \(error)")
        }
    }

    func isRunning() -> Bool {
        isRunningState
    }

    func setConnectionApprovalHandler(_ handler: @escaping ConnectionApprovalHandler) {
        log.debug("Setting connection approval handler")
        self.connectionApprovalHandler = handler
    }

    func start() async {
        log.info("Starting network manager")
        isRunningState = true

        guard let discoveryManager = discoveryManager else {
            log.error("Cannot start network manager: discovery manager not initialized")
            return
        }

        await discoveryManager.start(
            stateHandler: { [weak self] (state: NWListener.State) -> Void in
                guard let strongSelf = self else { return }

                Task {
                    await strongSelf.handleListenerStateChange(state)
                }
            },
            connectionHandler: { [weak self] (connection: NWConnection) -> Void in
                guard let strongSelf = self else { return }

                Task {
                    await strongSelf.handleNewConnection(connection)
                }
            }
        )

        // Monitor listener health and auto-restart if it stops advertising.
        Task {
            while self.isRunningState {
                if let currentDM = self.discoveryManager,
                    self.isRunningState
                {
                    let listenerState: NWListener.State = await currentDM.listener.state

                    if listenerState != .ready {
                        log.warning(
                            "Listener not in ready state, current state: \\(listenerState)"
                        )

                        let shouldAttemptRestart: Bool
                        switch listenerState {
                        case .failed, .cancelled:
                            shouldAttemptRestart = true
                        default:
                            shouldAttemptRestart = false
                        }

                        if shouldAttemptRestart {
                            log.info(
                                "Attempting to restart listener (state: \\(listenerState)) because it was failed or cancelled."
                            )
                            try? await currentDM.restartWithRandomPort()
                        }
                    }
                }

                try? await Task.sleep(nanoseconds: 10_000_000_000)  // 10s
            }
        }
    }

    private func handleListenerStateChange(_ state: NWListener.State) async {
        switch state {
        case .ready:
            log.info("Server ready and advertising via Bonjour as \(serviceType)")
        case .setup:
            log.debug("Server setting up...")
        case .waiting(let error):
            log.warning("Server waiting: \(error)")

            // If the port is already in use, try a new one.
            if error.errorCode == 48 {
                log.error("Port already in use, will try to restart service")

                try? await Task.sleep(nanoseconds: 2_000_000_000)  // 2 seconds

                if isRunningState {
                    try? await discoveryManager?.restartWithRandomPort()
                }
            }
        case .failed(let error):
            log.error("Server failed: \(error)")

            // Attempt recovery after a brief delay.
            if isRunningState {
                log.info("Attempting to recover from server failure")
                try? await Task.sleep(nanoseconds: 1_000_000_000)  // 1 second

                try? await discoveryManager?.restartWithRandomPort()
            }
        case .cancelled:
            log.info("Server cancelled")
        @unknown default:
            log.warning("Unknown server state")
        }
    }

    func stop() async {
        log.info("Stopping network manager")
        isRunningState = false

        for (id, connectionManager) in connections {
            log.debug("Stopping connection: \(id)")
            await connectionManager.stop()
            connectionTasks[id]?.cancel()
        }

        connections.removeAll()
        connectionTasks.removeAll()
        pendingConnections.removeAll()

        await discoveryManager?.stop()
    }

    func removeConnection(_ id: UUID) async {
        log.debug("Removing connection: \(id)")

        cancelAllResourceSubscriptions(connectionID: id)

        if let connectionManager = connections[id] {
            await connectionManager.stop()
        }

        if let task = connectionTasks[id] {
            task.cancel()
        }

        connections.removeValue(forKey: id)
        connectionTasks.removeValue(forKey: id)
        pendingConnections.removeValue(forKey: id)
    }

    private func storeResourceSubscription(
        connectionID: UUID,
        uri: String,
        token: ResourceSubscriptionToken
    ) {
        var subs = resourceSubscriptions[connectionID, default: [:]]
        subs[uri]?.cancel()
        subs[uri] = token
        resourceSubscriptions[connectionID] = subs
    }

    private func cancelResourceSubscription(connectionID: UUID, uri: String) {
        resourceSubscriptions[connectionID]?[uri]?.cancel()
        resourceSubscriptions[connectionID]?.removeValue(forKey: uri)
    }

    private func cancelAllResourceSubscriptions(connectionID: UUID) {
        guard let subs = resourceSubscriptions[connectionID] else { return }
        for (_, token) in subs { token.cancel() }
        resourceSubscriptions.removeValue(forKey: connectionID)
    }

    func notifyResourceUpdated(connectionID: UUID, uri: String) async {
        guard let connectionManager = connections[connectionID] else { return }
        await connectionManager.notifyResourceUpdated(uri: uri)
    }

    // Handle new incoming connections.
    private func handleNewConnection(_ connection: NWConnection) async {
        let connectionID = UUID()
        log.info("Handling new connection: \(connectionID)")

        let connectionManager = MCPConnectionManager(
            connectionID: connectionID,
            connection: connection,
            parentManager: self
        )

        connections[connectionID] = connectionManager

        // Drive the MCP handshake and approval flow.
        let task = Task {
            // Ensure this task is removed so the timeout logic doesn't fire afterward.
            defer {
                self.connectionTasks.removeValue(forKey: connectionID)
            }

            do {
                guard let approvalHandler = self.connectionApprovalHandler else {
                    log.error("No connection approval handler set, rejecting connection")
                    await removeConnection(connectionID)
                    return
                }

                try await connectionManager.start { clientInfo in
                    await approvalHandler(connectionID, clientInfo)
                }

                log.notice("Connection \(connectionID) successfully established")
            } catch {
                log.error("Failed to establish connection \(connectionID): \(error)")
                await removeConnection(connectionID)
            }
        }

        connectionTasks[connectionID] = task

        // Time out stalled setups to avoid orphaned connections.
        Task {
            try? await Task.sleep(nanoseconds: 10_000_000_000)  // 10 seconds

            // If the setup task is still registered, treat it as timed out.
            if self.connectionTasks[connectionID] != nil,
                self.connections[connectionID] != nil
            {
                log.warning(
                    "Connection \(connectionID) setup timed out (task still in registry), closing it"
                )
                await removeConnection(connectionID)
            }
        }
    }

    func registerHandlers(for server: MCP.Server, connectionID: UUID) async {
        await server.withMethodHandler(ListPrompts.self) { _ in
            log.debug("Handling ListPrompts request for \(connectionID)")
            return ListPrompts.Result(prompts: [])
        }

        await server.withMethodHandler(ListResources.self) { _ in
            log.debug("Handling ListResources request for \(connectionID)")
            return ListResources.Result(resources: [])
        }

        await server.withMethodHandler(ListResourceTemplates.self) { [weak self] _ in
            guard let self = self else {
                return ListResourceTemplates.Result(templates: [])
            }

            log.debug("Handling ListResourceTemplates request for \(connectionID)")

            var templates: [MCP.Resource.Template] = []
            if await self.isEnabledState {
                for service in await self.services {
                    let serviceId = String(describing: type(of: service))
                    guard await self.isServiceEnabled(serviceId) else { continue }
                    for template in service.resourceTemplates {
                        templates.append(
                            .init(
                                uriTemplate: template.uriTemplate,
                                name: template.name,
                                description: template.description,
                                mimeType: template.mimeType
                            )
                        )
                    }
                }
            }

            log.info("Returning \(templates.count) resource templates for \(connectionID)")
            return ListResourceTemplates.Result(templates: templates)
        }

        await server.withMethodHandler(ReadResource.self) { [weak self] params in
            guard let self = self else {
                throw MCPError.internalError("Server unavailable")
            }

            log.notice("ReadResource request for \(connectionID): \(params.uri)")

            guard await self.isEnabledState else {
                throw MCPError.invalidRequest("iMCP-MY is currently disabled")
            }

            for service in await self.services {
                let serviceId = String(describing: type(of: service))
                guard await self.isServiceEnabled(serviceId) else { continue }
                if let content = try await service.read(resource: params.uri) {
                    return ReadResource.Result(contents: [content])
                }
            }

            throw MCPError.invalidParams("No handler for URI: \(params.uri)")
        }

        await server.withMethodHandler(ResourceSubscribe.self) { [weak self] params in
            guard let self = self else { return Empty() }

            log.notice("ResourceSubscribe request for \(connectionID): \(params.uri)")

            guard await self.isEnabledState else {
                throw MCPError.invalidRequest("iMCP-MY is currently disabled")
            }

            let onChange: @Sendable (String) -> Void = { [weak self] changedURI in
                Task { [weak self] in
                    guard let self else { return }
                    await self.notifyResourceUpdated(
                        connectionID: connectionID,
                        uri: changedURI
                    )
                }
            }

            for service in await self.services {
                let serviceId = String(describing: type(of: service))
                guard await self.isServiceEnabled(serviceId) else { continue }
                if let token = try await service.subscribe(
                    resource: params.uri,
                    onChange: onChange
                ) {
                    await self.storeResourceSubscription(
                        connectionID: connectionID,
                        uri: params.uri,
                        token: token
                    )
                    return Empty()
                }
            }

            throw MCPError.invalidParams("Could not subscribe to: \(params.uri)")
        }

        await server.withMethodHandler(ResourceUnsubscribe.self) { [weak self] params in
            guard let self = self else { return Empty() }
            log.notice("ResourceUnsubscribe request for \(connectionID): \(params.uri)")
            await self.cancelResourceSubscription(
                connectionID: connectionID,
                uri: params.uri
            )
            return Empty()
        }

        await server.withMethodHandler(ListTools.self) { [weak self] _ in
            guard let self = self else {
                return ListTools.Result(tools: [])
            }

            log.debug("Handling ListTools request for \(connectionID)")

            var tools: [MCP.Tool] = []
            if await self.isEnabledState {
                for service in await self.services {
                    let serviceId = String(describing: type(of: service))
                    if await self.isServiceEnabled(serviceId) {
                        let schemaEncoder = JSONEncoder()
                        let schemaDecoder = JSONDecoder()
                        for tool in service.tools {
                            log.debug("Adding tool: \(tool.name)")
                            let schemaValue: Value
                            do {
                                let data = try schemaEncoder.encode(tool.inputSchema)
                                schemaValue = try schemaDecoder.decode(Value.self, from: data)
                            } catch {
                                log.error(
                                    "Failed to encode inputSchema for \(tool.name): \(error.localizedDescription)"
                                )
                                continue
                            }
                            tools.append(
                                .init(
                                    name: tool.name,
                                    description: tool.description,
                                    inputSchema: schemaValue,
                                    annotations: tool.annotations
                                )
                            )
                        }
                    }
                }
            }

            log.info("Returning \(tools.count) available tools for \(connectionID)")
            return ListTools.Result(tools: tools)
        }

        await server.withMethodHandler(CallTool.self) { [weak self] params in
            guard let self = self else {
                return CallTool.Result(
                    content: [.text(text: "Server unavailable", annotations: nil, _meta: nil)],
                    isError: true
                )
            }

            log.notice("Tool call received from \(connectionID): \(params.name)")

            guard await self.isEnabledState else {
                log.notice("Tool call rejected: iMCP-MY is disabled")
                return CallTool.Result(
                    content: [.text(text: "iMCP-MY is currently disabled. Please enable it to use tools.", annotations: nil, _meta: nil)],
                    isError: true
                )
            }

            for service in await self.services {
                let serviceId = String(describing: type(of: service))

                if await self.isServiceEnabled(serviceId) {
                    do {
                        guard
                            let value = try await service.call(
                                tool: params.name,
                                with: params.arguments ?? [:]
                            )
                        else {
                            continue
                        }

                        log.notice("Tool \(params.name) executed successfully for \(connectionID)")
                        switch value {
                        case .data(let mimeType?, let data) where mimeType.hasPrefix("audio/"):
                            return CallTool.Result(
                                content: [
                                    .audio(
                                        data: data.base64EncodedString(),
                                        mimeType: mimeType,
                                        annotations: nil,
                                        _meta: nil
                                    )
                                ],
                                isError: false
                            )
                        case .data(let mimeType?, let data) where mimeType.hasPrefix("image/"):
                            return CallTool.Result(
                                content: [
                                    .image(
                                        data: data.base64EncodedString(),
                                        mimeType: mimeType,
                                        annotations: nil,
                                        _meta: nil
                                    )
                                ],
                                isError: false
                            )
                        default:
                            let encoder = JSONEncoder()
                            encoder.userInfo[Ontology.DateTime.timeZoneOverrideKey] =
                                TimeZone.current
                            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]

                            let data = try encoder.encode(value)
                            let text = String(data: data, encoding: .utf8)!

                            return CallTool.Result(content: [.text(text: text, annotations: nil, _meta: nil)], isError: false)
                        }
                    } catch {
                        log.error(
                            "Error executing tool \(params.name): \(error.localizedDescription)"
                        )
                        return CallTool.Result(content: [.text(text: "Error: \(error)", annotations: nil, _meta: nil)], isError: true)
                    }
                }
            }

            log.error("Tool not found or service not enabled: \(params.name)")
            return CallTool.Result(
                content: [.text(text: "Tool not found or service not enabled: \(params.name)", annotations: nil, _meta: nil)],
                isError: true
            )
        }
    }

    // Update the enabled state and notify clients.
    func setEnabled(_ enabled: Bool) async {
        // Only act on changes.
        guard isEnabledState != enabled else { return }

        isEnabledState = enabled
        log.info("iMCP-MY enabled state changed to: \(enabled)")

        // Notify all connected clients that the tool list has changed.
        for (_, connectionManager) in connections {
            Task {
                await connectionManager.notifyToolListChanged()
            }
        }
    }

    // Called by the UI when service toggles change so connected MCP clients
    // get a tools/list_changed notification and re-fetch the tool list.
    func notifyServiceBindingsChanged() async {
        for (_, connectionManager) in connections {
            await connectionManager.notifyToolListChanged()
        }
    }
}
