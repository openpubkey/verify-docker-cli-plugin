package render

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
)

var out = os.Stderr
var red = lipgloss.Color("9")
var green = lipgloss.Color("10")

const paddingPerNestingLevel = 2

type Renderer struct {
	nestingLevel int
}

func (r *Renderer) AddNesting() *Renderer {
	return &Renderer{nestingLevel: r.nestingLevel + 1}
}

func (r *Renderer) Success(format string, a ...any) {
	str := fmt.Sprintf(format, a...)
	check := lipgloss.NewStyle().Foreground(green).Render(CheckSuccess)
	r.renderWithPrefix(check, str)
}

func (r *Renderer) Failure(format string, a ...any) {
	str := fmt.Sprintf(format, a...)
	check := lipgloss.NewStyle().Foreground(red).Render(CheckFailure)
	r.renderWithPrefix(check, str)
}

func (r *Renderer) Render(format string, a ...any) {
	str := fmt.Sprintf(format, a...)
	output := lipgloss.NewStyle().PaddingLeft(r.nestingLevel * paddingPerNestingLevel).Render(str)
	fmt.Fprintln(os.Stderr, output)
}

func (r *Renderer) NewLine() {
	fmt.Fprintln(os.Stderr)
}

func (r *Renderer) renderWithPrefix(prefix, str string) {
	str = fmt.Sprintf("%s %s", prefix, str)
	r.Render(str)
}

func NewRenderer() *Renderer {
	return &Renderer{nestingLevel: 0}
}
