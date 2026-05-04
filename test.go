package main; import ("fmt"; "github.com/charmbracelet/lipgloss"); func main() { s := lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true, false, true, false); fmt.Println(s.Render("Hello")) }
