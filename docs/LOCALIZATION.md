# NSD Localization Guide

NSD supports multiple languages through its built-in internationalization (i18n) system.

## Supported Languages

NSD includes translations for over 30 languages, including the top 10 most spoken languages worldwide:

1. **Chinese (Mandarin)** - `zh.json`
2. **Spanish** - `es.json`  
3. **English** - `en.json` (default)
4. **Hindi** - `hi.json`
5. **Arabic** - `ar.json`
6. **Portuguese** - `pt.json`
7. **Bengali** - `bn.json`
8. **Russian** - `ru.json`
9. **Japanese** - `ja.json`
10. **French** - `fr.json`

Additional supported languages include: German (de), Italian (it), Korean (ko), Turkish (tr), Vietnamese (vi), Polish (pl), Dutch (nl), Thai (th), Swedish (sv), Norwegian (no), Finnish (fi), Greek (el), Romanian (ro), and many more.

## Using Localization

To run NSD in a different language, use the `-i18n-file` flag:

```bash
# Run in Spanish
sudo ./nsd -i eth0 -i18n-file examples/i18n/es.json

# Run in Chinese
sudo ./nsd -i eth0 -i18n-file examples/i18n/zh.json

# Run in French
sudo ./nsd -i eth0 -i18n-file examples/i18n/fr.json
```

## Translation File Format

Translation files are in JSON format with key-value pairs:

```json
{
  "network_traffic": "Tráfico de red",
  "connections": "Conexiones",
  "bandwidth": "Ancho de banda"
}
```

## Adding New Languages

To add a new language:

1. Copy `examples/i18n/en.json` to a new file (e.g., `examples/i18n/de.json`)
2. Translate all values to the target language
3. Use the new file with the `-i18n-file` flag

## Customizing Translations

You can create custom translation files anywhere on your system:

```bash
# Use a custom translation file
sudo ./nsd -i eth0 -i18n-file /path/to/my-translations.json
```

## Translation Keys

The application uses the following main categories of translation keys:

- **UI Elements**: `network_traffic`, `connections`, `bandwidth`, etc.
- **Menu Items**: `help`, `quit`, `cancel`, `options`
- **Table Headers**: `source`, `destination`, `proto`, `bytes`
- **System Messages**: `requires_root`, `run_as_root`
- **Flag Descriptions**: `flag_i_desc`, `flag_theme_desc`, etc.

## Contributing Translations

To contribute new translations or improve existing ones:

1. Fork the repository
2. Add or update translation files in `examples/i18n/`
3. Ensure all keys from `en.json` are present
4. Submit a pull request

## Default Language

If no `-i18n-file` is specified, NSD uses English as the default language with built-in translations defined in `pkg/ui/i18n/i18n.go`.