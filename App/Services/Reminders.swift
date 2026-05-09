import EventKit
import Foundation
import MCP
import OSLog

private let log = Logger.service("reminders")

// Formatter for reminder output dates. Produces timezone-qualified ISO 8601
// (e.g. 2026-04-22T17:00:00-07:00) so agents can round-trip values back to
// `reminders_create` via the parser in Foundation+Extensions.
private let reminderOutputDateFormatter: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime]
    return f
}()

final class RemindersService: Service {
    private let eventStore = EKEventStore()

    static let shared = RemindersService()

    var isActivated: Bool {
        get async {
            return EKEventStore.authorizationStatus(for: .reminder) == .fullAccess
        }
    }

    func activate() async throws {
        let granted = try await eventStore.requestFullAccessToReminders()
        guard granted else {
            throw NSError(
                domain: "RemindersError",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Reminders access not authorized"]
            )
        }
    }

    var tools: [Tool] {
        Tool(
            name: "reminders_lists",
            description: "List available reminder lists",
            inputSchema: .object(
                properties: [:],
                additionalProperties: false
            ),
            annotations: .init(
                title: "List Reminder Lists",
                readOnlyHint: true,
                openWorldHint: false
            )
        ) { arguments in
            guard EKEventStore.authorizationStatus(for: .reminder) == .fullAccess else {
                log.error("Reminders access not authorized")
                throw NSError(
                    domain: "RemindersError",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Reminders access not authorized"]
                )
            }

            let reminderLists = self.eventStore.calendars(for: .reminder)

            return reminderLists.map { reminderList in
                Value.object([
                    "title": .string(reminderList.title),
                    "source": .string(reminderList.source.title),
                    "color": .string(reminderList.color.accessibilityName),
                    "isEditable": .bool(reminderList.allowsContentModifications),
                    "isSubscribed": .bool(reminderList.isSubscribed),
                ])
            }
        }

        Tool(
            name: "reminders_fetch",
            description: "Get reminders from the reminders app with flexible filtering options",
            inputSchema: .object(
                properties: [
                    "completed": .boolean(
                        description:
                            "If true, fetch completed reminders; if false, fetch incomplete; if omitted, fetch all"
                    ),
                    "start": .string(
                        description:
                            "Start date/time range for fetching reminders. If timezone is omitted, local time is assumed. Date-only uses local midnight.",
                        format: .dateTime
                    ),
                    "end": .string(
                        description:
                            "End date/time range for fetching reminders. If timezone is omitted, local time is assumed. Date-only uses local midnight.",
                        format: .dateTime
                    ),
                    "lists": .array(
                        description:
                            "Names of reminder lists to fetch from; if empty, fetches from all lists",
                        items: .string()
                    ),
                    "query": .string(
                        description: "Text to search for in reminder titles"
                    ),
                ],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Fetch Reminders",
                readOnlyHint: true,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()

            guard EKEventStore.authorizationStatus(for: .reminder) == .fullAccess else {
                log.error("Reminders access not authorized")
                throw NSError(
                    domain: "RemindersError",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Reminders access not authorized"]
                )
            }

            // Filter reminder lists based on provided names
            var reminderLists = self.eventStore.calendars(for: .reminder)
            if case .array(let listNames) = arguments["lists"],
                !listNames.isEmpty
            {
                let requestedNames = Set(
                    listNames.compactMap { $0.stringValue?.lowercased() }
                )
                reminderLists = reminderLists.filter {
                    requestedNames.contains($0.title.lowercased())
                }
            }

            // Parse dates if provided
            var startDate: Date? = nil
            var endDate: Date? = nil
            var startIsDateOnly = false
            var endIsDateOnly = false

            if case .string(let start) = arguments["start"],
                let parsedStart = ISO8601DateFormatter.parsedLenientISO8601Date(
                    fromISO8601String: start
                )
            {
                startDate = parsedStart.date
                startIsDateOnly = parsedStart.isDateOnly
            }
            if case .string(let end) = arguments["end"],
                let parsedEnd = ISO8601DateFormatter.parsedLenientISO8601Date(
                    fromISO8601String: end
                )
            {
                endDate = parsedEnd.date
                endIsDateOnly = parsedEnd.isDateOnly
            }

            let calendar = Calendar.current
            if let startDateValue = startDate {
                startDate = calendar.normalizedStartDate(
                    from: startDateValue,
                    isDateOnly: startIsDateOnly
                )
            }
            if let endDateValue = endDate {
                endDate = calendar.normalizedEndDate(from: endDateValue, isDateOnly: endIsDateOnly)
            }

            // Create predicate based on completion status
            let predicate: NSPredicate
            if case .bool(let completed) = arguments["completed"] {
                if completed {
                    predicate = self.eventStore.predicateForCompletedReminders(
                        withCompletionDateStarting: startDate,
                        ending: endDate,
                        calendars: reminderLists
                    )
                } else {
                    predicate = self.eventStore.predicateForIncompleteReminders(
                        withDueDateStarting: startDate,
                        ending: endDate,
                        calendars: reminderLists
                    )
                }
            } else {
                // If completion status not specified, use incomplete predicate as default
                predicate = self.eventStore.predicateForReminders(in: reminderLists)
            }

            // Fetch reminders
            let reminders = try await withCheckedThrowingContinuation { continuation in
                self.eventStore.fetchReminders(matching: predicate) { fetchedReminders in
                    continuation.resume(returning: fetchedReminders ?? [])
                }
            }

            // Apply additional filters
            var filteredReminders = reminders

            // Filter by search text if provided
            if case .string(let searchText) = arguments["query"],
                !searchText.isEmpty
            {
                filteredReminders = filteredReminders.filter {
                    $0.title?.localizedCaseInsensitiveContains(searchText) == true
                }
            }

            return filteredReminders.map(Self.encode)
        }

        Tool(
            name: "reminders_create",
            description: "Create a new reminder with specified properties",
            inputSchema: .object(
                properties: [
                    "title": .string(),
                    "due": .string(
                        description:
                            "Due date/time for the reminder. If timezone is omitted, local time is assumed. Date-only uses local midnight.",
                        format: .dateTime
                    ),
                    "list": .string(
                        description: "Reminder list name (uses default if not specified)"
                    ),
                    "notes": .string(),
                    "priority": .string(
                        default: .string(EKReminderPriority.none.stringValue),
                        enum: EKReminderPriority.allCases.map { .string($0.stringValue) }
                    ),
                    "alarms": .array(
                        description: "Minutes before due date to set alarms",
                        items: .integer()
                    ),
                ],
                required: ["title"],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Create Reminder",
                destructiveHint: true,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()

            guard EKEventStore.authorizationStatus(for: .reminder) == .fullAccess else {
                log.error("Reminders access not authorized")
                throw NSError(
                    domain: "RemindersError",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Reminders access not authorized"]
                )
            }

            let reminder = EKReminder(eventStore: self.eventStore)

            // Set required properties
            guard case .string(let title) = arguments["title"] else {
                throw NSError(
                    domain: "RemindersError",
                    code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Reminder title is required"]
                )
            }
            reminder.title = title

            // Set calendar (list)
            var calendar = self.eventStore.defaultCalendarForNewReminders()
            if case .string(let listName) = arguments["list"] {
                if let matchingCalendar = self.eventStore.calendars(for: .reminder)
                    .first(where: { $0.title.lowercased() == listName.lowercased() })
                {
                    calendar = matchingCalendar
                }
            }
            reminder.calendar = calendar

            // Set optional properties
            if case .string(let dueDateStr) = arguments["due"],
                let parsedDueDate = ISO8601DateFormatter.parsedLenientISO8601Date(
                    fromISO8601String: dueDateStr
                )
            {
                let calendar = Calendar.current
                let dueDate = calendar.normalizedStartDate(
                    from: parsedDueDate.date,
                    isDateOnly: parsedDueDate.isDateOnly
                )
                reminder.dueDateComponents = calendar.dateComponents(
                    [.year, .month, .day, .hour, .minute, .second],
                    from: dueDate
                )
            }

            if case .string(let notes) = arguments["notes"] {
                reminder.notes = notes
            }

            if case .string(let priorityStr) = arguments["priority"] {
                reminder.priority = Int(EKReminderPriority.from(string: priorityStr).rawValue)
            }

            // Set alarms
            if case .array(let alarmMinutes) = arguments["alarms"] {
                reminder.alarms = alarmMinutes.compactMap {
                    guard case .int(let minutes) = $0 else { return nil }
                    return EKAlarm(relativeOffset: TimeInterval(-minutes * 60))
                }
            }

            // Save the reminder
            try self.eventStore.save(reminder, commit: true)

            return Self.encode(reminder)
        }

        Tool(
            name: "reminders_update",
            description:
                "Update an existing reminder by id (from `reminders_fetch`). Use `completed: true` to mark it done. Only fields present in the request are changed; pass an empty string to clear `notes`, `url`, `location`, or `due`, or an empty array to clear `alarms`.",
            inputSchema: .object(
                properties: [
                    "id": .string(
                        description: "Reminder identifier (the `id` from `reminders_fetch`)."
                    ),
                    "title": .string(),
                    "notes": .string(),
                    "due": .string(
                        description:
                            "New due date/time. Empty string clears the due date. If timezone is omitted, local time is assumed.",
                        format: .dateTime
                    ),
                    "list": .string(
                        description: "Move the reminder to a different list (matched case-insensitively)."
                    ),
                    "priority": .string(
                        enum: EKReminderPriority.allCases.map { .string($0.stringValue) }
                    ),
                    "completed": .boolean(
                        description: "Mark the reminder completed (true) or uncompleted (false)."
                    ),
                    "url": .string(
                        description: "Associated URL. Empty string clears it."
                    ),
                    "location": .string(
                        description: "Free-text location. Empty string clears it."
                    ),
                    "alarms": .array(
                        description:
                            "Replaces all existing alarms. Each entry is minutes before the due date; empty array removes all alarms.",
                        items: .integer()
                    ),
                ],
                required: ["id"],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Update Reminder",
                destructiveHint: true,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()

            guard EKEventStore.authorizationStatus(for: .reminder) == .fullAccess else {
                log.error("Reminders access not authorized")
                throw NSError(
                    domain: "RemindersError",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Reminders access not authorized"]
                )
            }

            guard case .string(let id) = arguments["id"], !id.isEmpty else {
                throw NSError(
                    domain: "RemindersError",
                    code: 3,
                    userInfo: [NSLocalizedDescriptionKey: "`id` is required"]
                )
            }

            guard let item = self.eventStore.calendarItem(withIdentifier: id),
                let reminder = item as? EKReminder
            else {
                throw NSError(
                    domain: "RemindersError",
                    code: 4,
                    userInfo: [NSLocalizedDescriptionKey: "No reminder found with id \(id)"]
                )
            }

            if case .string(let title) = arguments["title"], !title.isEmpty {
                reminder.title = title
            }

            if case .string(let notes) = arguments["notes"] {
                reminder.notes = notes.isEmpty ? nil : notes
            }

            if case .bool(let completed) = arguments["completed"] {
                reminder.isCompleted = completed
            }

            if case .string(let priorityStr) = arguments["priority"] {
                reminder.priority = Int(EKReminderPriority.from(string: priorityStr).rawValue)
            }

            if case .string(let dueStr) = arguments["due"] {
                if dueStr.isEmpty {
                    reminder.dueDateComponents = nil
                } else if let parsedDue = ISO8601DateFormatter.parsedLenientISO8601Date(
                    fromISO8601String: dueStr
                ) {
                    let calendar = Calendar.current
                    let dueDate = calendar.normalizedStartDate(
                        from: parsedDue.date,
                        isDateOnly: parsedDue.isDateOnly
                    )
                    reminder.dueDateComponents = calendar.dateComponents(
                        [.year, .month, .day, .hour, .minute, .second],
                        from: dueDate
                    )
                }
            }

            if case .string(let listName) = arguments["list"], !listName.isEmpty {
                if let matchingCalendar = self.eventStore.calendars(for: .reminder)
                    .first(where: { $0.title.lowercased() == listName.lowercased() })
                {
                    reminder.calendar = matchingCalendar
                }
            }

            if case .string(let urlStr) = arguments["url"] {
                reminder.url = urlStr.isEmpty ? nil : URL(string: urlStr)
            }

            if case .string(let location) = arguments["location"] {
                reminder.location = location.isEmpty ? nil : location
            }

            if case .array(let alarmMinutes) = arguments["alarms"] {
                reminder.alarms = alarmMinutes.compactMap {
                    guard case .int(let minutes) = $0 else { return nil }
                    return EKAlarm(relativeOffset: TimeInterval(-minutes * 60))
                }
            }

            try self.eventStore.save(reminder, commit: true)

            return Self.encode(reminder)
        }

        Tool(
            name: "reminders_delete",
            description:
                "Permanently delete one or more reminders by id (from `reminders_fetch`).",
            inputSchema: .object(
                properties: [
                    "ids": .array(
                        description:
                            "Reminder identifiers to delete.",
                        items: .string()
                    )
                ],
                required: ["ids"],
                additionalProperties: false
            ),
            annotations: .init(
                title: "Delete Reminders",
                destructiveHint: true,
                openWorldHint: false
            )
        ) { arguments in
            try await self.activate()

            guard EKEventStore.authorizationStatus(for: .reminder) == .fullAccess else {
                log.error("Reminders access not authorized")
                throw NSError(
                    domain: "RemindersError",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Reminders access not authorized"]
                )
            }

            guard case .array(let rawIds) = arguments["ids"] else {
                throw NSError(
                    domain: "RemindersError",
                    code: 3,
                    userInfo: [NSLocalizedDescriptionKey: "`ids` must be an array of strings"]
                )
            }

            let ids = rawIds.compactMap { $0.stringValue }
            guard !ids.isEmpty else {
                throw NSError(
                    domain: "RemindersError",
                    code: 3,
                    userInfo: [
                        NSLocalizedDescriptionKey: "`ids` must contain at least one identifier"
                    ]
                )
            }

            var deleted: [Value] = []
            var notFound: [Value] = []

            for id in ids {
                guard let item = self.eventStore.calendarItem(withIdentifier: id),
                    let reminder = item as? EKReminder
                else {
                    notFound.append(.string(id))
                    continue
                }
                try self.eventStore.remove(reminder, commit: true)
                deleted.append(.string(id))
            }

            var result: [String: Value] = ["deleted": .array(deleted)]
            if !notFound.isEmpty {
                result["notFound"] = .array(notFound)
            }
            return Value.object(result)
        }
    }

    /// Encodes an EKReminder for the `reminders_fetch` and `reminders_create`
    /// responses. Emits a superset of what `PlanAction(EKReminder)` used to
    /// surface — adds alarms, location, hasAlarms, start/completion dates,
    /// recurrence flag, and identifier. Optional fields are omitted when
    /// absent (not emitted as null) to keep payloads compact.
    static func encode(_ reminder: EKReminder) -> Value {
        var obj: [String: Value] = [:]

        obj["id"] = .string(reminder.calendarItemIdentifier)
        obj["title"] = .string(reminder.title ?? "")
        if let notes = reminder.notes, !notes.isEmpty {
            obj["notes"] = .string(notes)
        }
        if let list = reminder.calendar {
            obj["list"] = .string(list.title)
        }
        obj["priority"] = .string(priorityString(for: reminder.priority))
        obj["isCompleted"] = .bool(reminder.isCompleted)

        if let due = reminder.dueDateComponents?.date {
            obj["due"] = .string(reminderOutputDateFormatter.string(from: due))
        }
        if let start = reminder.startDateComponents?.date {
            obj["startDate"] = .string(reminderOutputDateFormatter.string(from: start))
        }
        if let completion = reminder.completionDate {
            obj["completionDate"] = .string(reminderOutputDateFormatter.string(from: completion))
        }
        if let url = reminder.url {
            obj["url"] = .string(url.absoluteString)
        }
        if let location = reminder.location, !location.isEmpty {
            obj["location"] = .string(location)
        }

        let alarms = reminder.alarms ?? []
        obj["hasAlarms"] = .bool(!alarms.isEmpty)
        if !alarms.isEmpty {
            obj["alarms"] = .array(alarms.map(Self.encode))
        }

        if let rules = reminder.recurrenceRules, !rules.isEmpty {
            obj["isRecurring"] = .bool(true)
        }

        if let modified = reminder.lastModifiedDate {
            obj["lastModified"] = .string(reminderOutputDateFormatter.string(from: modified))
        }

        return .object(obj)
    }

    /// Encodes an EKAlarm as a tagged-union object mirroring the alarm input
    /// schema accepted by `events_create` (Calendar.swift:260-338). Round-
    /// trippable back through `reminders_create` for the "relative" case.
    static func encode(_ alarm: EKAlarm) -> Value {
        var obj: [String: Value] = [:]

        if alarm.proximity != .none,
            let location = alarm.structuredLocation,
            let geo = location.geoLocation
        {
            obj["type"] = .string("proximity")
            obj["proximity"] = .string(alarm.proximity == .enter ? "enter" : "leave")
            obj["locationTitle"] = .string(location.title ?? "")
            obj["latitude"] = .double(geo.coordinate.latitude)
            obj["longitude"] = .double(geo.coordinate.longitude)
            if location.radius > 0 {
                obj["radius"] = .double(location.radius)
            }
        } else if let absoluteDate = alarm.absoluteDate {
            obj["type"] = .string("absolute")
            obj["datetime"] = .string(
                reminderOutputDateFormatter.string(from: absoluteDate)
            )
        } else {
            // `reminders_create` takes positive "minutes before due", so we
            // emit the same convention: offset -900s -> minutes 15.
            obj["type"] = .string("relative")
            obj["minutes"] = .int(Int((-alarm.relativeOffset / 60).rounded()))
        }

        if let sound = alarm.soundName, !sound.isEmpty {
            obj["sound"] = .string(sound)
        }
        if let email = alarm.emailAddress, !email.isEmpty {
            obj["emailAddress"] = .string(email)
        }

        return .object(obj)
    }

    private static func priorityString(for priority: Int) -> String {
        // EKReminder.priority maps to buckets in the Reminders UI:
        // 0 = none, 1-4 = high, 5 = medium, 6-9 = low.
        switch priority {
        case 1...4: return EKReminderPriority.high.stringValue
        case 5: return EKReminderPriority.medium.stringValue
        case 6...9: return EKReminderPriority.low.stringValue
        default: return EKReminderPriority.none.stringValue
        }
    }
}
