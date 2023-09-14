package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/zawachte/etcdmon/pkg/checks"
)

const corporate = `Leverage agile frameworks to provide a robust synopsis for high level overviews. Iterative approaches to corporate strategy foster collaborative thinking to further the overall value proposition. Organically grow the holistic world view of disruptive innovation via workplace diversity and empowerment.

Bring to the table win-win survival strategies to ensure proactive domination. At the end of the day, going forward, a new normal that has evolved from generation X is on the runway heading towards a streamlined cloud solution. User generated content in real-time will have multiple touchpoints for offshoring.

Capitalize on low hanging fruit to identify a ballpark value added activity to beta test. Override the digital divide with additional clickthroughs from DevOps. Nanotechnology immersion along the information highway will close the loop on focusing solely on the bottom line.

[yellow]Press Enter, then Tab/Backtab for word selections`

func main() {

	app := tview.NewApplication()

	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetChangedFunc(func() {
			app.Draw()
		})
	numSelections := 0

	go checks.Fsslower(context.Background(), textView)

	textView.SetDoneFunc(func(key tcell.Key) {
		currentSelection := textView.GetHighlights()
		if key == tcell.KeyEnter {
			if len(currentSelection) > 0 {
				textView.Highlight()
			} else {
				textView.Highlight("0").ScrollToHighlight()
			}
		} else if len(currentSelection) > 0 {
			index, _ := strconv.Atoi(currentSelection[0])
			if key == tcell.KeyTab {
				index = (index + 1) % numSelections
			} else if key == tcell.KeyBacktab {
				index = (index - 1 + numSelections) % numSelections
			} else {
				return
			}
			textView.Highlight(strconv.Itoa(index)).ScrollToHighlight()
		}
	})

	frame := tview.NewFrame(textView).
		SetBorders(0, 0, 0, 0, 0, 0)
	frame.SetBorder(true).
		SetTitle(fmt.Sprintf(`fsslower`))

	textView1 := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetChangedFunc(func() {
			app.Draw()
		})
	numSelections1 := 0

	go checks.Biotop(context.Background(), textView1)

	textView1.SetDoneFunc(func(key tcell.Key) {
		currentSelection := textView.GetHighlights()
		if key == tcell.KeyEnter {
			if len(currentSelection) > 0 {
				textView.Highlight()
			} else {
				textView.Highlight("0").ScrollToHighlight()
			}
		} else if len(currentSelection) > 0 {
			index, _ := strconv.Atoi(currentSelection[0])
			if key == tcell.KeyTab {
				index = (index + 1) % numSelections1
			} else if key == tcell.KeyBacktab {
				index = (index - 1 + numSelections1) % numSelections1
			} else {
				return
			}
			textView1.Highlight(strconv.Itoa(index)).ScrollToHighlight()
		}
	})

	frame2 := tview.NewFrame(textView1).
		SetBorders(0, 0, 0, 0, 0, 0)
	frame2.SetBorder(true).
		SetTitle(fmt.Sprintf(`biotop`))

	flex := tview.NewFlex().
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			//AddItem(tview.NewBox().SetBorder(true).SetTitle("etcdmon"), 0, 1, false).
			AddItem(frame, 0, 2, false).
			AddItem(frame2, 0, 2, false), 0, 2, false)

	fram1 := tview.NewFrame(flex).
		SetBorders(0, 0, 0, 0, 0, 0)
	fram1.SetTitle(fmt.Sprintf(`etcdmon`))

	if err := app.SetRoot(fram1, true).SetFocus(fram1).Run(); err != nil {
		panic(err)
	}
}
