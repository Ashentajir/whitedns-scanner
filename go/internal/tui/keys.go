package tui

import "github.com/charmbracelet/bubbles/key"

type KeyMap struct {
	Pause  key.Binding
	Resume key.Binding
	Help   key.Binding
	Quit   key.Binding
}

var DefaultKeyMap = KeyMap{
	Pause: key.NewBinding(
		key.WithKeys("p", "P", "ح"),
		key.WithHelp("p", "pause"),
	),
	Resume: key.NewBinding(
		key.WithKeys("r", "R", "ق"),
		key.WithHelp("r", "resume"),
	),
	Help: key.NewBinding(
		key.WithKeys("h", "H", "؟"),
		key.WithHelp("h", "help"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "Q", "ض", "ctrl+c"),
		key.WithHelp("q", "stop & save"),
	),
}
