package tui

import (
	"context"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/willj4945/cloudcomply/internal/nist"
)

type view int

const (
	viewDashboard view = iota
	viewFindings
)

// FindingsFetcher sources findings and an org summary — from demo data or a
// live AWS call, the tui package doesn't need to know which.
type FindingsFetcher func(ctx context.Context) ([]nist.Finding, nist.OrgSummary, error)

// findingsMsg carries the result of an async FindingsFetcher call back into
// the Bubble Tea update loop.
type findingsMsg struct {
	findings []nist.Finding
	org      nist.OrgSummary
	err      error
}

func fetchCmd(fetch FindingsFetcher) tea.Cmd {
	return func() tea.Msg {
		findings, org, err := fetch(context.Background())
		return findingsMsg{findings: findings, org: org, err: err}
	}
}

type model struct {
	// shared
	currentView view
	quitting    bool
	fetch       FindingsFetcher
	loading     bool
	loadErr     error
	spinner     spinner.Model

	// dashboard
	orgName         string
	accountCount    int
	isOrgMode       bool
	complianceScore int
	selected        int
	menuItems       []string
	message         string

	// findings browser
	findings      []nist.Finding
	findingsTable table.Model
	families      []string
	familyIdx     int
	familyFilter  string
	impactLevels  []string
	impactIdx     int
	impactFilter  string
}

func initialModel(fetch FindingsFetcher) model {
	families := []string{"ALL", "AC", "AU", "CM", "IA", "SC", "SI"}
	impactLevels := []string{"ALL", string(nist.IL2), string(nist.IL4), string(nist.IL5), string(nist.IL6)}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("63"))

	return model{
		currentView: viewDashboard,
		fetch:       fetch,
		loading:     true,
		spinner:     s,
		selected:    0,
		menuItems: []string{
			"Run Full NIST Compliance Scan",
			"Browse Findings by Control Family",
			"Generate Threat Model",
			"View Best Practices Report",
			"Quit",
		},
		findingsTable: buildTable(nil, "ALL", "ALL"),
		families:      families,
		familyIdx:     0,
		familyFilter:  "ALL",
		impactLevels:  impactLevels,
		impactIdx:     0,
		impactFilter:  "ALL",
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, fetchCmd(m.fetch))
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case findingsMsg:
		m.loading = false
		if msg.err != nil {
			m.loadErr = msg.err
			return m, nil
		}
		m.findings = msg.findings
		m.orgName = msg.org.Name
		m.accountCount = msg.org.AccountCount
		m.isOrgMode = msg.org.IsOrgMode
		m.complianceScore = nist.ComplianceScore(m.findings)
		m.findingsTable = buildTable(m.findings, m.familyFilter, m.impactFilter)
		return m, nil
	case spinner.TickMsg:
		if !m.loading {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

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
		m.loading = true
		m.loadErr = nil
		m.message = ""
		return m, tea.Batch(m.spinner.Tick, fetchCmd(m.fetch))
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
				m.findingsTable = buildTable(m.findings, m.familyFilter, m.impactFilter)
			}
			return m, nil
		case "right", "l":
			if m.familyIdx < len(m.families)-1 {
				m.familyIdx++
				m.familyFilter = m.families[m.familyIdx]
				m.findingsTable = buildTable(m.findings, m.familyFilter, m.impactFilter)
			}
			return m, nil
		case "[":
			if m.impactIdx > 0 {
				m.impactIdx--
				m.impactFilter = m.impactLevels[m.impactIdx]
				m.findingsTable = buildTable(m.findings, m.familyFilter, m.impactFilter)
			}
			return m, nil
		case "]":
			if m.impactIdx < len(m.impactLevels)-1 {
				m.impactIdx++
				m.impactFilter = m.impactLevels[m.impactIdx]
				m.findingsTable = buildTable(m.findings, m.familyFilter, m.impactFilter)
			}
			return m, nil
		}
	}

	// Pass remaining key events (up/down/etc.) to the table.
	var cmd tea.Cmd
	m.findingsTable, cmd = m.findingsTable.Update(msg)
	return m, cmd
}
