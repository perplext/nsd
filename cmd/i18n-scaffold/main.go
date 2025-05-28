package main

import (
  "bytes"
  "encoding/json"
  "fmt"
  "io/ioutil"
  "net/http"
  "os"
  "path/filepath"
  "sort"
  "strings"

  "github.com/perplext/nsd/pkg/ui/i18n"
)

func main() {
  // directory with JSON translation files, default to examples/i18n
  dir := "examples/i18n"
  if len(os.Args) > 1 {
    dir = os.Args[1]
  }
  pattern := filepath.Join(dir, "*.json")
  files, err := filepath.Glob(pattern)
  if err != nil {
    fmt.Fprintf(os.Stderr, "Error finding JSON files: %v\n", err)
    os.Exit(1)
  }
  for _, f := range files {
    data, err := ioutil.ReadFile(f)
    if err != nil {
      fmt.Fprintf(os.Stderr, "Failed to read %s: %v\n", f, err)
      continue
    }
    var m map[string]string
    if err := json.Unmarshal(data, &m); err != nil {
      fmt.Fprintf(os.Stderr, "Failed to parse %s: %v\n", f, err)
      continue
    }
    // ensure all keys present
    for key := range i18n.Translations {
      if _, exists := m[key]; !exists {
        m[key] = ""
      }
    }
    // translate any empty values via API
    langCode := strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
    for key, val := range m {
      if val == "" {
        if defVal, ok := i18n.Translations[key]; ok {
          m[key] = translate(defVal, langCode)
        }
      }
    }
    // order keys for readability
    keys := make([]string, 0, len(m))
    for k := range m {
      keys = append(keys, k)
    }
    sort.Strings(keys)
    out := make(map[string]string, len(m))
    for _, k := range keys {
      out[k] = m[k]
    }
    b, err := json.MarshalIndent(out, "", "  ")
    if err != nil {
      fmt.Fprintf(os.Stderr, "Failed to marshal %s: %v\n", f, err)
      continue
    }
    if err := ioutil.WriteFile(f, append(b, '\n'), 0644); err != nil {
      fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", f, err)
      continue
    }
    fmt.Printf("Translated %s\n", f)
  }
}

// translate uses LibreTranslate API to translate text from English to target language.
func translate(text, target string) string {
  reqBody := map[string]string{
    "q":      text,
    "source": "en",
    "target": target,
    "format": "text",
  }
  body, _ := json.Marshal(reqBody)
  resp, err := http.Post("https://libretranslate.de/translate", "application/json", bytes.NewReader(body))
  if err != nil {
    fmt.Fprintf(os.Stderr, "Translation error [%s]: %v\n", target, err)
    return text
  }
  defer resp.Body.Close()
  var res map[string]interface{}
  if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
    fmt.Fprintf(os.Stderr, "Decode error [%s]: %v\n", target, err)
    return text
  }
  if tr, ok := res["translatedText"].(string); ok {
    return tr
  }
  return text
}
