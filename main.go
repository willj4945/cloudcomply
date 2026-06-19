package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

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

	metricStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("42")) // green for good score

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			MarginTop(1)
)

// ====================== MODEL ======================
type model struct {
	orgName         string
	accountCount    int
	complianceScore int // NIST 800-53 / RMF compliance %
	selected        int
	menuItems       []string
	quitting        bool
	message         string // temporary status message
}

func initialModel() model {
	return model{
		orgName:         "Acme Federal Org",
		accountCount:    47,
		complianceScore: 87,
		selected:        0,
		menuItems: []string{
			"Run Full NIST Compliance Scan",
			"Browse Findings by Control Family",
			"Generate Threat Model",
			"View Best Practices Report",
			"Quit",
		},
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
	case 0: // Run NIST Scan (fake for now)
		m.message = "🔄 Starting NIST compliance scan across 47 accounts..."
		// In real version: return a tea.Cmd that calls AWS SDK + updates model
	case 1: // Browse Findings
		m.message = "📊 Opening findings browser (table view coming next)..."
	case 2: // Threat Model
		m.message = "🛡️ Launching interactive threat modeling wizard..."
	case 3: // Best Practices
		m.message = "✅ Generating best practices report..."
	case 4: // Quit
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) View() string {
	if m.quitting {
		return "Thanks for using cloudcomply! Exiting...\n"
	}

	// Header
	header := titleStyle.Render("cloudcomply — AWS Org Compliance Dashboard")

	// Summary box
	summary := fmt.Sprintf(
		"Organization: %s\nAccounts in Org: %d\nNIST 800-53 Compliance: %d%%",
		m.orgName, m.accountCount, m.complianceScore,
	)
	summaryBox := boxStyle.Render(summary)

	// Menu
	menu := "Main Menu:\n\n"
	for i, item := range m.menuItems {
		cursor := "  "
		if m.selected == i {
			cursor = "→ "
			menu += cursor + selectedMenuStyle.Render(item) + "\n"
		} else {
			menu += cursor + menuStyle.Render(item) + "\n"
		}
	}

	// Status message area
	status := ""
	if m.message != "" {
		status = "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render(m.message)
	}

	help := helpStyle.Render("↑/k ↓/j: navigate • enter: select • q: quit")

	return fmt.Sprintf(
		"%s\n\n%s\n\n%s%s\n\n%s",
		header, summaryBox, menu, status, help,
	)
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running program: %v\n", err)
		os.Exit(1)
	}
}
