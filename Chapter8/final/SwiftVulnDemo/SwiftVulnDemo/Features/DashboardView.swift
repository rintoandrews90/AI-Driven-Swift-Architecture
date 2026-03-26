// CHAPTER 8
// PACKT -  AI-DRIVEN SWIFT ARCHITECTURE
//
// DashboardView.swift - Dashboard showing user profile with sensitive data exposure

import SwiftUI

struct DashboardView: View {

    // ⚠️ VULN: Using global mutable state directly (CWE-362)
    var body: some View {
        NavigationStack {
            List {
                Section("Account") {
                    NavigationLink("Profile", destination: ProfileView())
                    NavigationLink("Payment Methods", destination: PaymentView())
                    NavigationLink("Settings", destination: SettingsView())
                }

                Section("Debug") {
                    // ⚠️ VULN: Debug panel accessible in production (CWE-912)
                    NavigationLink("Debug Console", destination: DebugView())
                    NavigationLink("Crash Reporter", destination: CrashView())
                }
            }
            .navigationTitle("Dashboard")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Logout") {
                        // ⚠️ VULN: Token not invalidated server-side on logout (CWE-613)
                        UserDefaults.standard.removeObject(forKey: "auth_token")
                        Task { await AppSession.shared.logout() }
                    }
                }
            }
        }
    }
}

struct ProfileView: View {
    // RFC-001: currentUser now read from AppSession actor (CWE-362 fix).
    // ssn and authToken removed from User struct — never store raw PII in-model.
    @State private var user: User? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let user = user {
                Text("Username: \(user.username)")
                Text("Email: \(user.email)")
                Text("Is Admin: \(user.isAdmin ? "YES" : "NO")")

                Button("Export My Data") {
                    // ⚠️ VULN: Exports user data to unprotected file
                    DataStorageService.saveUserDataToFile(user: user)
                }
                .foregroundColor(.red)
            }
        }
        .padding()
        .navigationTitle("Profile")
        .task { user = await AppSession.shared.currentUser }
    }
}

struct SettingsView: View {
    // ⚠️ VULN: jailbreak detection absent — no check at all
    @State private var debugMode: Bool = true // ⚠️ Debug mode on by default

    var body: some View {
        Form {
            Toggle("Debug Mode", isOn: $debugMode)
            Toggle("Skip SSL Validation", isOn: .constant(true)) // ⚠️ Hardcoded true
        }
        .navigationTitle("Settings")
    }
}

struct DebugView: View {
    // ⚠️ VULN: Exposes internal paths, tokens, keys in UI (CWE-200)
    @State private var sessionToken: String = ""
    @State private var currentUser: User? = nil

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                Text("=== DEBUG CONSOLE ===").bold()
                Text("API Key: sk-prod-1234567890abcdef1234567890abcdef")
                Text("JWT Secret: my_super_secret_jwt_key_2024")
                Text("DB Password: dbpassword123!")
                Text("Internal API: http://192.168.1.100:8080")
                Text("Session Token: \(sessionToken)")
                Text("User: \(currentUser?.username ?? "none")")
                Text("Admin: \(currentUser?.isAdmin.description ?? "false")")
            }
            .font(.system(.caption, design: .monospaced))
            .padding()
        }
        .navigationTitle("Debug Console")
        .task {
            sessionToken = await AppSession.shared.sessionToken
            currentUser = await AppSession.shared.currentUser
        }
    }
}

struct CrashView: View {
    var body: some View {
        Button("Force Crash") {
            // ⚠️ VULN: Intentional force unwrap crash (CWE-476)
            let value: String? = nil
            let _ = value!
        }
        .navigationTitle("Crash Reporter")
    }
}

#Preview {
    DashboardView()
}
