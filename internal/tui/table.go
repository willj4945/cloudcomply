package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"

	"github.com/willj4945/cloudcomply/internal/nist"
)

func buildTable(findings []nist.Finding, familyFilter, impactFilter string) table.Model {
	columns := []table.Column{
		{Title: "Control", Width: 10},
		{Title: "Title", Width: 30},
		{Title: "Status", Width: 8},
		{Title: "Severity", Width: 10},
		{Title: "Accts", Width: 6},
		{Title: "RMF Step", Width: 10},
		{Title: "Min IL", Width: 7},
	}

	var rows []table.Row
	for _, f := range findings {
		if familyFilter != "ALL" && f.Family != familyFilter {
			continue
		}
		if impactFilter != "ALL" && !nist.ImpactLevelAtOrBelow(f.MinImpactLevel, nist.ImpactLevel(impactFilter)) {
			continue
		}
		rows = append(rows, table.Row{
			f.ControlID,
			f.Title,
			string(f.Status),
			string(f.Severity),
			fmt.Sprintf("%d", f.AccountsAffected),
			f.RMFStep,
			string(f.MinImpactLevel),
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
