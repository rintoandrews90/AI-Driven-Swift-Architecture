import SwiftUI

struct ContentView: View {

    @State private var notes: [Note] = [
        Note(
            id: 1,
            title: "Meeting",
            content: "Discuss Q4 goals",
            priority: .high
        ),
        Note(
            id: 2,
            title: "Shopping",
            content: "Milk, eggs, bread",
            priority: .low
        ),
        Note(
            id: 3,
            title: "Ideas",
            content: "New app features",
            priority: .medium
        )
    ]

    @State private var showingNewNote = false
    @State private var nextId = 4

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Header with status indicator
                HStack {
                    Text("My Notes")
                        .font(.title)
                        .fontWeight(.bold)

                    Spacer()

                    // WCAG 1.4.1: Color is not the only visual means — pair circle with text label
                    // WCAG 1.4.1 (semantic): Green = notes present (active), gray = empty
                    HStack(spacing: 4) {
                        Circle()
                            .fill(notes.isEmpty ? Color.gray : Color.green)
                            .frame(width: 10, height: 10)
                            .accessibilityHidden(true)
                        Text(notes.isEmpty ? "Empty" : "\(notes.count) active")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                            .accessibilityHidden(true)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("Notes status")
                    .accessibilityValue(notes.isEmpty ? "No notes" : "\(notes.count) active notes")
                    .accessibilityHint("Shows whether the note list contains active items")
                }
                .padding()
                .background(Color(.systemGray6))

                // Notes list
                List {
                    ForEach(notes, id: \.id) { note in
                        NoteRowView(note: note)
                            // ACCESSIBILITY ISSUE #2: No accessibility container
                    }
                }
                .listStyle(.plain)
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    // WCAG 2.5.5: Frame must be on Button, not only on Image, for 44×44pt touch target
                    Button(action: { showingNewNote = true }) {
                        Image(systemName: "plus")
                            .font(.headline)
                            .foregroundColor(.blue)
                    }
                    .frame(width: 44, height: 44)
                    .contentShape(Rectangle())
                    .accessibilityLabel("Add new note")
                    .accessibilityHint("Double tap to create a new note")
                    .accessibilityIdentifier("add-note-button")
                }
            }
        }
        .sheet(isPresented: $showingNewNote) {
            NewNoteView(
                notes: $notes,
                nextId: $nextId
            )
        }
    }
}







enum NotePriority {
    case high, medium, low
}

#Preview {
    ContentView()
}
