import SwiftUI

struct NoteRowView: View {
    let note: Note

    var body: some View {
        HStack(spacing: 8) {
            // WCAG 4.1.2: Inner container combined separately so delete button stays independently accessible.
            // Applying .accessibilityElement(children: .combine) on the outer HStack absorbed the delete
            // button into the row element, making it unreachable for assistive technologies.
            HStack(spacing: 8) {
                Rectangle()
                    .fill(priorityColor(note.priority))
                    .frame(width: 4)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 4) {
                    Text(note.title)
                        .font(.headline)

                    // WCAG 1.4.3: .secondary adapts to light/dark mode and meets contrast ratio;
                    // .gray is a fixed color that can fail 4.5:1 on white backgrounds.
                    Text(note.content)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }

                Spacer()
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(note.title), \(priorityLabel(note.priority)) priority, \(note.content)")
            .accessibilityHint("Double tap to view or edit note")
            .accessibilityIdentifier("note-row-\(note.id)")

            // Delete button remains a separate accessibility element
            Button(action: {}) {
                Image(systemName: "trash")
                    .foregroundColor(.red)
                    .font(.system(size: 14))
            }
            .frame(width: 44, height: 44)
            .contentShape(Rectangle())
            .accessibilityLabel("Delete \(note.title) note")
            .accessibilityHint("Double tap to delete this note")
            .accessibilityIdentifier("delete-note-\(note.id)")
        }
        .padding(.vertical, 8)
    }

    private func priorityColor(_ priority: NotePriority) -> Color {
        switch priority {
        case .high: .red
        case .medium: .orange
        case .low: .green
        }
    }

    private func priorityLabel(_ priority: NotePriority) -> String {
        switch priority {
        case .high: "high"
        case .medium: "medium"
        case .low: "low"
        }
    }
}
