package ui

import (
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"time"
	
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	neterrors "github.com/perplext/nsd/pkg/errors"
)

// ErrorDisplay handles error display in the UI
type ErrorDisplay struct {
	app         *tview.Application
	pages       *tview.Pages
	errorLog    []ErrorEntry
	maxErrors   int
	showErrors  bool
}

// ErrorEntry represents a logged error
type ErrorEntry struct {
	Time     time.Time
	Level    string // "error", "warning", "info"
	Message  string
	Details  string
}

// NewErrorDisplay creates a new error display handler
func NewErrorDisplay(app *tview.Application, pages *tview.Pages) *ErrorDisplay {
	return &ErrorDisplay{
		app:       app,
		pages:     pages,
		errorLog:  make([]ErrorEntry, 0),
		maxErrors: 100,
		showErrors: true,
	}
}

// HandleError displays an error to the user
func (ed *ErrorDisplay) HandleError(err error) {
	if err == nil {
		return
	}
	
	entry := ErrorEntry{
		Time:    time.Now(),
		Level:   "error",
		Message: err.Error(),
		Details: fmt.Sprintf("%+v", err),
	}
	
	ed.logError(entry)
	
	if ed.showErrors {
		ed.showErrorModal(entry)
	}
}

// HandleWarning displays a warning to the user
func (ed *ErrorDisplay) HandleWarning(message string) {
	entry := ErrorEntry{
		Time:    time.Now(),
		Level:   "warning",
		Message: message,
	}
	
	ed.logError(entry)
}

// logError logs an error entry
func (ed *ErrorDisplay) logError(entry ErrorEntry) {
	ed.errorLog = append(ed.errorLog, entry)
	
	// Trim if too many errors
	if len(ed.errorLog) > ed.maxErrors {
		ed.errorLog = ed.errorLog[len(ed.errorLog)-ed.maxErrors:]
	}
	
	// Also log to standard logger
	log.Printf("[%s] %s: %s", entry.Level, entry.Time.Format("15:04:05"), entry.Message)
}

// showErrorModal displays an error in a modal
func (ed *ErrorDisplay) showErrorModal(entry ErrorEntry) {
	if ed.app == nil {
		return
	}
	
	// Format message
	message := fmt.Sprintf("[%s] %s\n\n%s",
		entry.Time.Format("15:04:05"),
		strings.ToUpper(entry.Level),
		entry.Message,
	)
	
	// Create modal
	modal := tview.NewModal().
		SetText(message).
		AddButtons([]string{"OK", "Details", "Disable Errors"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			switch buttonIndex {
			case 0: // OK
				if ed.pages != nil {
					ed.pages.RemovePage("error")
				}
			case 1: // Details
				ed.showErrorDetails(entry)
			case 2: // Disable
				ed.showErrors = false
				if ed.pages != nil {
					ed.pages.RemovePage("error")
				}
			}
		})
	
	// Show modal
	ed.app.QueueUpdateDraw(func() {
		if ed.pages != nil {
			ed.pages.AddPage("error", modal, true, true)
		}
	})
}

// showErrorDetails shows detailed error information
func (ed *ErrorDisplay) showErrorDetails(entry ErrorEntry) {
	textView := tview.NewTextView().
		SetText(fmt.Sprintf("Time: %s\nLevel: %s\nMessage: %s\n\nDetails:\n%s\n\nStack Trace:\n%s",
			entry.Time.Format("2006-01-02 15:04:05"),
			entry.Level,
			entry.Message,
			entry.Details,
			string(debug.Stack()),
		)).
		SetScrollable(true).
		SetWrap(true)
	
	textView.SetBorder(true).SetTitle("Error Details")
	
	// Add close handler
	textView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape || event.Rune() == 'q' {
			if ed.pages != nil {
				ed.pages.RemovePage("error-details")
			}
			return nil
		}
		return event
	})
	
	if ed.pages != nil {
		ed.pages.AddPage("error-details", textView, true, true)
	}
}

// GetErrorLog returns the error log
func (ed *ErrorDisplay) GetErrorLog() []ErrorEntry {
	return ed.errorLog
}

// ClearErrorLog clears the error log
func (ed *ErrorDisplay) ClearErrorLog() {
	ed.errorLog = ed.errorLog[:0]
}

// SafeUIOperation executes a UI operation with panic recovery
func SafeUIOperation(operation func(), component string, onError func(error)) {
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("panic in %s: %v\nStack: %s", component, r, debug.Stack())
			log.Printf("UI panic recovered: %v", err)
			if onError != nil {
				onError(err)
			}
		}
	}()
	
	operation()
}

// UIErrorHandler provides centralized error handling for UI components
type UIErrorHandler struct {
	display       *ErrorDisplay
	fallbackMode  bool
	maxRetries    int
	retryDelay    time.Duration
}

// NewUIErrorHandler creates a new UI error handler
func NewUIErrorHandler(app *tview.Application, pages *tview.Pages) *UIErrorHandler {
	return &UIErrorHandler{
		display:      NewErrorDisplay(app, pages),
		maxRetries:   3,
		retryDelay:   time.Second,
	}
}

// HandleWithRetry handles an operation with retry logic
func (h *UIErrorHandler) HandleWithRetry(operation func() error, component string) error {
	var lastErr error
	
	for attempt := 0; attempt <= h.maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(h.retryDelay)
		}
		
		err := operation()
		if err == nil {
			return nil
		}
		
		lastErr = err
		
		// Check if retryable
		if !neterrors.IsRetryable(err) {
			h.display.HandleError(neterrors.WrapUIError(component, "operation", err))
			return err
		}
	}
	
	// Max retries exceeded
	h.display.HandleError(fmt.Errorf("max retries exceeded in %s: %w", component, lastErr))
	return lastErr
}

// EnableFallbackMode enables a simplified UI mode for error conditions
func (h *UIErrorHandler) EnableFallbackMode() {
	h.fallbackMode = true
	h.display.HandleWarning("Entering fallback mode due to errors")
}

// IsInFallbackMode returns whether fallback mode is enabled
func (h *UIErrorHandler) IsInFallbackMode() bool {
	return h.fallbackMode
}