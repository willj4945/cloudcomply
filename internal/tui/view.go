package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"cloudcomply/internal/nist"
)

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

	if m.loading {
		return fmt.Sprintf("%s\n\n  %s Loading findings...\n", header, m.spinner.View())
	}

	if m.loadErr != nil {
		errBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("196")).
			Padding(1, 2).
			Margin(1, 2).
			Width(70).
			Foreground(lipgloss.Color("196")).
			Render(fmt.Sprintf("Failed to load Security Hub findings:\n%v\n\nRetry, or run with --demo for offline demo data.", m.loadErr))
		help := helpStyle.Render("q: quit")
		return fmt.Sprintf("%s\n\n%s\n\n%s", header, errBox, help)
	}

	scoreColor := "42" // green
	if m.complianceScore < 70 {
		scoreColor = "196" // red
	} else if m.complianceScore < 85 {
		scoreColor = "214" // orange
	}
	scoreStr := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(scoreColor)).
		Render(fmt.Sprintf("%d%% compliant", m.complianceScore))

	il5Score := nist.ComplianceScoreForImpactLevel(m.findings, nist.IL5)
	il5Color := "42" // green
	if il5Score < 70 {
		il5Color = "196" // red
	} else if il5Score < 85 {
		il5Color = "214" // orange
	}
	il5Str := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(il5Color)).
		Render(fmt.Sprintf("%d%% ready", il5Score))

	orgLabel, accountsLabel := "Organization:", "Accounts in Org:"
	if !m.isOrgMode {
		orgLabel, accountsLabel = "Account:", "Accounts Scanned:"
	}
	summary := fmt.Sprintf(
		"%-29s%s\n%-29s%d\n%-29s%s\n%-29s%s",
		orgLabel, m.orgName,
		accountsLabel, m.accountCount,
		"NIST 800-53:", scoreStr,
		"DoD SRG (IL5 Mission Owner):", il5Str,
	)
	summaryBox := boxStyle.Render(summary)
	if !m.isOrgMode {
		summaryBox += "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("214")).
			Render("ℹ Single-account mode — no AWS Organization detected. Org-wide scoring will apply once org access is available.")
	}

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

	// Impact Level filter tabs
	ilTabs := make([]string, len(m.impactLevels))
	for i, l := range m.impactLevels {
		if i == m.impactIdx {
			ilTabs[i] = selectedMenuStyle.Render(fmt.Sprintf("[%s]", l))
		} else {
			ilTabs[i] = menuStyle.Render(fmt.Sprintf(" %s ", l))
		}
	}

	tabBar := "Family:       " + strings.Join(tabs, "")
	ilTabBar := "Impact Level: " + strings.Join(ilTabs, "")
	stats := tallyLine(nist.Summarize(filterFindings(m.findings, m.familyFilter, m.impactFilter)))

	help := helpStyle.Render("↑/k ↓/j: scroll • ←/→ h/l: filter family • [/]: filter impact level • esc/q: back")

	return fmt.Sprintf("%s\n\n%s\n%s\n%s\n\n%s\n%s",
		header,
		tabBar,
		ilTabBar,
		stats,
		tableBoxStyle.Render(m.findingsTable.View()),
		help,
	)
}

// tallyLine omits N/A and error counts when zero so the common Security Hub
// case reads exactly as before.
func tallyLine(t nist.Tally) string {
	parts := []string{
		passStyle.Render(fmt.Sprintf("✓ %d passed", t.Passed)),
		failStyle.Render(fmt.Sprintf("✗ %d failed", t.Failed)),
	}
	if t.Errors > 0 {
		parts = append(parts, errorStyle.Render(fmt.Sprintf("! %d error", t.Errors)))
	}
	if t.NotApplicable > 0 {
		parts = append(parts, naStyle.Render(fmt.Sprintf("– %d n/a", t.NotApplicable)))
	}
	return "  " + strings.Join(parts, "   ")
}
