package tui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
		Foreground(lipgloss.Color("#7bdff2")).
			Align(lipgloss.Center)

	wrapperStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#7bdff2")).
			Padding(1, 2)

	stateRunningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#8affc1")).Bold(true)
	statePausedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffe066")).Bold(true)
	stateStoppedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff6b6b")).Bold(true)

	tableHeaderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#7bdff2")).Bold(true)

	greenText   = lipgloss.NewStyle().Foreground(lipgloss.Color("#8affc1")).Bold(true)
	yellowText  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffe066")).Bold(true)
	redText     = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff6b6b")).Bold(true)
	cyanText    = lipgloss.NewStyle().Foreground(lipgloss.Color("#7bdff2")).Bold(true)
	magentaText = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff85a1")).Bold(true)
	deepPurple  = lipgloss.NewStyle().Foreground(lipgloss.Color("#5e60ce"))

	dimStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#9aa5b1"))

	integrityCleanStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#8affc1")).Bold(true)
	integrityPoisonedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff85a1")).Bold(true)
)

func statusColor(status int) lipgloss.Style {
	if status < 300 {
		return greenText
	}
	if status < 400 {
		return cyanText
	}
	if status < 500 {
		return yellowText
	}
	return redText
}

func latencyColor(latency int) lipgloss.Style {
	if latency < 200 {
		return greenText
	}
	if latency < 500 {
		return yellowText
	}
	return redText
}

// protocolColor returns a styled badge for DNS protocol names.
func protocolColor(proto string) lipgloss.Style {
	switch proto {
	case "UDP":
		return yellowText
	case "TCP":
		return cyanText
	case "DoT":
		return greenText
	case "DoH":
		return magentaText
	default:
		return lipgloss.NewStyle()
	}
}
