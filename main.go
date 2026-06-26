package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ====================== VIEWS ======================

type view int

const (
	viewDashboard view = iota
	viewFindings
)

// ====================== DATA TYPES ======================

type Severity string
type FindingStatus string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"

	StatusFailed FindingStatus = "FAILED"
	StatusPassed FindingStatus = "PASSED"
)

// Finding mirrors the shape of a real Security Hub NIST 800-53 finding.
// Switching from fake data to live AWS calls later means replacing demoFindings()
// without touching anything else.
type Finding struct {
	ControlID        string
	Title            string
	Family           string // e.g. "AC", "AU", "CM"
	Status           FindingStatus
	Severity         Severity
	AccountsAffected int
	RMFStep          string // e.g. "Assess", "Monitor", "Implement"
}

// ====================== FAKE DATA ======================

func demoFindings() []Finding {
	return []Finding{
		// AC — Access Control
		{"AC-2", "Account Management", "AC", StatusFailed, SeverityHigh, 12, "Assess"},
		{"AC-2(1)", "Auto Temp/Emergency Accounts", "AC", StatusPassed, SeverityLow, 0, "Monitor"},
		{"AC-3", "Access Enforcement", "AC", StatusPassed, SeverityMedium, 0, "Monitor"},
		{"AC-6", "Least Privilege", "AC", StatusFailed, SeverityHigh, 23, "Assess"},
		{"AC-17", "Remote Access", "AC", StatusFailed, SeverityMedium, 8, "Assess"},

		// AU — Audit and Accountability
		{"AU-2", "Event Logging", "AU", StatusPassed, SeverityMedium, 0, "Monitor"},
		{"AU-3", "Content of Audit Records", "AU", StatusFailed, SeverityMedium, 5, "Assess"},
		{"AU-9", "Protection of Audit Information", "AU", StatusFailed, SeverityHigh, 15, "Assess"},
		{"AU-12", "Audit Record Generation", "AU", StatusPassed, SeverityLow, 0, "Monitor"},

		// CM — Configuration Management
		{"CM-2", "Baseline Configuration", "CM", StatusFailed, SeverityCritical, 47, "Implement"},
		{"CM-6", "Configuration Settings", "CM", StatusFailed, SeverityHigh, 31, "Assess"},
		{"CM-7", "Least Functionality", "CM", StatusPassed, SeverityMedium, 0, "Monitor"},
		{"CM-8", "System Component Inventory", "CM", StatusFailed, SeverityMedium, 19, "Assess"},
		{"CM-11", "User-Installed Software", "CM", StatusPassed, SeverityLow, 0, "Monitor"},

		// IA — Identification and Authentication
		{"IA-2", "Identification and Authentication", "IA", StatusFailed, SeverityCritical, 38, "Assess"},
		{"IA-2(1)", "MFA for Privileged Accounts", "IA", StatusFailed, SeverityCritical, 41, "Implement"},
		{"IA-5", "Authenticator Management", "IA", StatusFailed, SeverityHigh, 22, "Assess"},
		{"IA-8", "Identification (Non-Org Users)", "IA", StatusPassed, SeverityMedium, 0, "Monitor"},

		// SC — System and Communications Protection
		{"SC-7", "Boundary Protection", "SC", StatusFailed, SeverityHigh, 14, "Assess"},
		{"SC-8", "Transmission Confidentiality", "SC", StatusPassed, SeverityMedium, 0, "Monitor"},
		{"SC-12", "Cryptographic Key Establishment", "SC", StatusFailed, SeverityMedium, 9, "Assess"},
		{"SC-28", "Protection of Info at Rest", "SC", StatusFailed, SeverityHigh, 27, "Assess"},
		{"SC-28(1)", "Cryptographic Protection", "SC", StatusPassed, SeverityMedium, 0, "Monitor"},

		// SI — System and Information Integrity
		{"SI-2", "Flaw Remediation", "SI", StatusFailed, SeverityHigh, 33, "Assess"},
		{"SI-3", "Malicious Code Protection", "SI", StatusPassed, SeverityMedium, 0, "Monitor"},
		{"SI-4", "System Monitoring", "SI", StatusFailed, SeverityMedium, 7, "Monitor"},
		{"SI-7", "Software and Firmware Integrity", "SI", StatusPassed, SeverityLow, 0, "Monitor"},
	}
}

func complianceScore(findings []Finding) int {
	if len(findings) == 0 {
		return 0
	}
	passed := 0
	for _, f := range findings {
		if f.Status == StatusPassed {
			passed++
		}
	}
	return (passed * 100) / len(findings)
}

// ====================== STYLES ======================

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("63")).
			MarginLeft(2)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(1, 2).
			Margin(1, 2)

	menuStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	selectedMenuStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("205"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			MarginTop(1)

	passStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	failStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))

	tableBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Margin(1, 2)
)

// ====================== TABLE ======================

func buildTable(findings []Finding, filter string) table.Model {
	columns := []table.Column{
		{Title: "Control", Width: 10},
		{Title: "Title", Width: 34},
		{Title: "Status", Width: 8},
		{Title: "Severity", Width: 10},
		{Title: "Accts", Width: 6},
		{Title: "RMF Step", Width: 10},
	}

	var rows []table.Row
	for _, f := range findings {
		if filter != "ALL" && f.Family != filter {
			continue
		}
		rows = append(rows, table.Row{
			f.ControlID,
			f.Title,
			string(f.Status),
			string(f.Severity),
			fmt.Sprintf("%d", f.AccountsAffected),
			f.RMFStep,
		})
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(15),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("63")).
		BorderBottom(true).
		Bold(true).
		Foreground(lipgloss.Color("63"))
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	return t
}

// ====================== MODEL ======================

type model struct {
	// shared
	currentView view
	quitting    bool

	// dashboard
	orgName         string
	accountCount    int
	complianceScore int
	selected        int
	menuItems       []string
	message         string

	// findings browser
	findings      []Finding
	findingsTable table.Model
	families      []string
	familyIdx     int
	familyFilter  string
}

func initialModel() model {
	findings := demoFindings()
	families := []string{"ALL", "AC", "AU", "CM", "IA", "SC", "SI"}

	return model{
		currentView:     viewDashboard,
		orgName:         "Acme Federal Org",
		accountCount:    47,
		complianceScore: complianceScore(findings),
		selected:        0,
		menuItems: []string{
			"Run Full NIST Compliance Scan",
			"Browse Findings by Control Family",
			"Generate Threat Model",
			"View Best Practices Report",
			"Quit",
		},
		findings:      findings,
		findingsTable: buildTable(findings, "ALL"),
		families:      families,
		familyIdx:     0,
		familyFilter:  "ALL",
	}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.currentView {
	case viewDashboard:
		return m.updateDashboard(msg)
	case viewFindings:
		return m.updateFindings(msg)
	}
	return m, nil
}

func (m model) updateDashboard(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			if m.selected > 0 {
				m.selected--
			}
		case "down", "j":
			if m.selected < len(m.menuItems)-1 {
				m.selected++
			}
		case "enter":
			return m.handleMenuSelection()
		}
	}
	return m, nil
}

func (m model) handleMenuSelection() (tea.Model, tea.Cmd) {
	switch m.selected {
	case 0:
		m.message = "Scan complete (demo mode). Results loaded below."
	case 1:
		m.currentView = viewFindings
		m.message = ""
	case 2:
		m.message = "Threat modeling wizard — coming soon."
	case 3:
		m.message = "Best practices report — coming soon."
	case 4:
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) updateFindings(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "q", "esc":
			m.currentView = viewDashboard
			return m, nil
		case "left", "h":
			if m.familyIdx > 0 {
				m.familyIdx--
				m.familyFilter = m.families[m.familyIdx]
				m.findingsTable = buildTable(m.findings, m.familyFilter)
			}
			return m, nil
		case "right", "l":
			if m.familyIdx < len(m.families)-1 {
				m.familyIdx++
				m.familyFilter = m.families[m.familyIdx]
				m.findingsTable = buildTable(m.findings, m.familyFilter)
			}
			return m, nil
		}
	}

	// Pass remaining key events (up/down/etc.) to the table.
	var cmd tea.Cmd
	m.findingsTable, cmd = m.findingsTable.Update(msg)
	return m, cmd
}

// ====================== VIEWS ======================

func (m model) View() string {
	if m.quitting {
		return "Exiting cloudcomply...\n"
	}
	switch m.currentView {
	case viewDashboard:
		return m.dashboardView()
	case viewFindings:
		return m.findingsView()
	}
	return ""
}

func (m model) dashboardView() string {
	header := titleStyle.Render("cloudcomply — AWS Org Compliance Dashboard")

	scoreColor := "42" // green
	if m.complianceScore < 70 {
		scoreColor = "196" // red
	} else if m.complianceScore < 85 {
		scoreColor = "214" // orange
	}
	scoreStr := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(scoreColor)).
		Render(fmt.Sprintf("%d%% compliant", m.complianceScore))

	summary := fmt.Sprintf(
		"Organization:    %s\nAccounts in Org: %d\nNIST 800-53:     %s",
		m.orgName, m.accountCount, scoreStr,
	)
	summaryBox := boxStyle.Render(summary)

	menu := "Main Menu:\n\n"
	for i, item := range m.menuItems {
		if m.selected == i {
			menu += "→ " + selectedMenuStyle.Render(item) + "\n"
		} else {
			menu += "  " + menuStyle.Render(item) + "\n"
		}
	}

	status := ""
	if m.message != "" {
		status = "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render(m.message)
	}

	help := helpStyle.Render("↑/k ↓/j: navigate • enter: select • q: quit")

	return fmt.Sprintf("%s\n\n%s\n\n%s%s\n\n%s", header, summaryBox, menu, status, help)
}

func (m model) findingsView() string {
	header := titleStyle.Render("NIST 800-53 Findings Browser")

	// Family filter tabs
	tabs := make([]string, len(m.families))
	for i, f := range m.families {
		if i == m.familyIdx {
			tabs[i] = selectedMenuStyle.Render(fmt.Sprintf("[%s]", f))
		} else {
			tabs[i] = menuStyle.Render(fmt.Sprintf(" %s ", f))
		}
	}

	// Pass/fail counts for current filter
	passed, failed := 0, 0
	for _, f := range m.findings {
		if m.familyFilter != "ALL" && f.Family != m.familyFilter {
			continue
		}
		if f.Status == StatusPassed {
			passed++
		} else {
			failed++
		}
	}

	tabBar := "Family:  " + strings.Join(tabs, "")
	stats := fmt.Sprintf("  %s   %s",
		passStyle.Render(fmt.Sprintf("✓ %d passed", passed)),
		failStyle.Render(fmt.Sprintf("✗ %d failed", failed)),
	)

	help := helpStyle.Render("↑/k ↓/j: scroll • ←/→ h/l: filter family • esc/q: back")

	return fmt.Sprintf("%s\n\n%s\n%s\n\n%s\n%s",
		header,
		tabBar,
		stats,
		tableBoxStyle.Render(m.findingsTable.View()),
		help,
	)
}

// ====================== MAIN ======================

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
