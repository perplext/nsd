package ui

import "github.com/gdamore/tcell/v2"

// Theme defines UI color scheme inspired by VSCode themes.
type Theme struct {
    BorderColor        tcell.Color
    TitleColor         tcell.Color
    PrimaryColor       tcell.Color
    SecondaryColor     tcell.Color
    PieBorderColor     tcell.Color
    PieTitleColor      tcell.Color
    StatusBarTextColor tcell.Color
    StatusBarBgColor   tcell.Color
}

// Themes holds predefined color schemes.
var Themes = map[string]Theme{
    "Dark+": {
        BorderColor:        tcell.NewRGBColor(0x00, 0x7A, 0xCC),
        TitleColor:         tcell.NewRGBColor(0x00, 0x7A, 0xCC),
        PrimaryColor:       tcell.NewRGBColor(0x0E, 0xBF, 0xE9),
        SecondaryColor:     tcell.NewRGBColor(0xD4, 0x42, 0xFF),
        PieBorderColor:     tcell.NewRGBColor(0x00, 0x7A, 0xCC),
        PieTitleColor:      tcell.NewRGBColor(0x00, 0x7A, 0xCC),
        StatusBarTextColor: tcell.ColorWhite,
        StatusBarBgColor:   tcell.ColorBlack,
    },
    "Light+": {
        BorderColor:        tcell.NewRGBColor(0x00, 0x00, 0x00),
        TitleColor:         tcell.NewRGBColor(0x00, 0x00, 0x00),
        PrimaryColor:       tcell.NewRGBColor(0x00, 0x64, 0x00),
        SecondaryColor:     tcell.NewRGBColor(0x00, 0x00, 0x8B),
        PieBorderColor:     tcell.NewRGBColor(0x00, 0x00, 0x00),
        PieTitleColor:      tcell.NewRGBColor(0x00, 0x00, 0x00),
        StatusBarTextColor: tcell.ColorBlack,
        StatusBarBgColor:   tcell.ColorWhite,
    },
    "Monokai": {
        BorderColor:        tcell.NewRGBColor(0xA6, 0xE2, 0x2E),
        TitleColor:         tcell.NewRGBColor(0xA6, 0xE2, 0x2E),
        PrimaryColor:       tcell.NewRGBColor(0xA6, 0xE2, 0x2E),
        SecondaryColor:     tcell.NewRGBColor(0x66, 0xD9, 0xEF),
        PieBorderColor:     tcell.NewRGBColor(0xA6, 0xE2, 0x2E),
        PieTitleColor:      tcell.NewRGBColor(0xA6, 0xE2, 0x2E),
        StatusBarTextColor: tcell.ColorWhite,
        StatusBarBgColor:   tcell.NewRGBColor(0x27, 0x28, 0x22),
    },
    "Solarized Dark": {
        BorderColor:        tcell.NewRGBColor(0x26, 0x8B, 0xD2),
        TitleColor:         tcell.NewRGBColor(0x26, 0x8B, 0xD2),
        PrimaryColor:       tcell.NewRGBColor(0xB5, 0x89, 0x00),
        SecondaryColor:     tcell.NewRGBColor(0x2A, 0xA1, 0x98),
        PieBorderColor:     tcell.NewRGBColor(0x26, 0x8B, 0xD2),
        PieTitleColor:      tcell.NewRGBColor(0x26, 0x8B, 0xD2),
        StatusBarTextColor: tcell.ColorWhite,
        StatusBarBgColor:   tcell.NewRGBColor(0x00, 0x2B, 0x36),
    },
    "Dracula": {
        BorderColor:        tcell.NewRGBColor(0xBD, 0x93, 0xF9),
        TitleColor:         tcell.NewRGBColor(0xBD, 0x93, 0xF9),
        PrimaryColor:       tcell.NewRGBColor(0x50, 0xFA, 0x7B),
        SecondaryColor:     tcell.NewRGBColor(0xFF, 0x79, 0xC6),
        PieBorderColor:     tcell.NewRGBColor(0xBD, 0x93, 0xF9),
        PieTitleColor:      tcell.NewRGBColor(0xBD, 0x93, 0xF9),
        StatusBarTextColor: tcell.ColorWhite,
        StatusBarBgColor:   tcell.NewRGBColor(0x28, 0x2A, 0x36),
    },
}
