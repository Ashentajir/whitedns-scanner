package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Map Python Rich colors to terminal hex approximations
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#9b30ff")).
			Align(lipgloss.Center)

	wrapperStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#9b30ff")).
			Padding(1, 2)

	stateRunningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true)
	statePausedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFF00")).Bold(true)
	stateStoppedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true)

	// Header and text colors tuned to match Python's Rich theme (bright_* equivalents)
	tableHeaderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#5A5A5A")).Bold(true)

	// Named color approximations used by the Python UI
	greenText   = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true) // bold green
	yellowText  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFF00")).Bold(true) // bold yellow
	redText     = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF3333")).Bold(true) // bold red
	cyanText    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Bold(true) // bold cyan
	magentaText = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF")).Bold(true) // bold magenta
	deepPurple  = lipgloss.NewStyle().Foreground(lipgloss.Color("#9b30ff"))            // deep purple

	// Dim text for credits and secondary info
	dimStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B6B6B"))

	// DNS Integrity badge styles
	integrityCleanStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF88")).Bold(true)
	integrityPoisonedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF3333")).Bold(true)
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
