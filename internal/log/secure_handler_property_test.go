package log

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// secretMarker is part of every value the generator places under a sensitive
// key, so a log line that contains it has leaked a secret.
const secretMarker = "s3cr3tvalue"

// groupValuer resolves to a group when the handler asks for its value, the
// way a type implementing slog.LogValuer hides its fields until logged.
type groupValuer []slog.Attr

func (g groupValuer) LogValue() slog.Value { return slog.GroupValue(g...) }

// stringValuer resolves to a string.
type stringValuer string

func (s stringValuer) LogValue() slog.Value { return slog.StringValue(string(s)) }

// attrGen draws an attribute tree. Under a sensitive key the value carries
// secretMarker; elsewhere it never does. Any value may be wrapped in a
// LogValuer and any attribute may be a group of further attributes.
func attrGen(depth int) *rapid.Generator[slog.Attr] {
	return rapid.Custom(func(t *rapid.T) slog.Attr {
		if depth > 0 && rapid.IntRange(0, 3).Draw(t, "group") == 0 {
			key := rapid.SampledFrom([]string{"request", "user", "meta"}).Draw(t, "group key")
			children := rapid.SliceOfN(attrGen(depth-1), 0, 3).Draw(t, "children")
			if rapid.Bool().Draw(t, "group valuer") {
				return slog.Any(key, groupValuer(children))
			}
			return slog.Attr{Key: key, Value: slog.GroupValue(children...)}
		}
		sensitive := rapid.Bool().Draw(t, "sensitive")
		var key, value string
		if sensitive {
			key = rapid.SampledFrom([]string{"password", "Authorization", "session_id", "api_token", "seed"}).Draw(t, "key")
			value = secretMarker + rapid.StringMatching(`[a-z]{0,4}`).Draw(t, "suffix")
		} else {
			key = rapid.SampledFrom([]string{"url", "status", "host", "keyboard"}).Draw(t, "key")
			value = rapid.StringMatching(`[a-z]{0,6}`).Draw(t, "value")
		}
		switch rapid.IntRange(0, 2).Draw(t, "form") {
		case 0:
			return slog.String(key, value)
		case 1:
			return slog.Any(key, stringValuer(value))
		default:
			return slog.Any(key, []byte(value))
		}
	})
}

// TestPropertySecureHandlerNeverWritesAValueUnderASensitiveKey checks the handler's
// promise for every way an attribute reaches it: on the record, through
// Logger.With, inside groups, and behind a LogValuer that resolves to a
// string or to a group.
func TestPropertySecureHandlerNeverWritesAValueUnderASensitiveKey(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		attrs := rapid.SliceOfN(attrGen(2), 1, 4).Draw(t, "attrs")
		withAttrs := rapid.SliceOfN(attrGen(1), 0, 2).Draw(t, "with")
		json := rapid.Bool().Draw(t, "json")

		var buf bytes.Buffer
		logger := NewSecureLogger(&buf, true)
		if json {
			logger = NewSecureJSONLogger(&buf, true)
		}
		if len(withAttrs) > 0 {
			args := make([]any, len(withAttrs))
			for i, a := range withAttrs {
				args[i] = a
			}
			logger = logger.With(args...)
		}
		if rapid.Bool().Draw(t, "with group") {
			logger = logger.WithGroup("scan")
		}
		args := make([]any, len(attrs))
		for i, a := range attrs {
			args[i] = a
		}
		logger.Info("event", args...)

		if strings.Contains(buf.String(), secretMarker) {
			t.Fatalf("secret written to the log: %s", buf.String())
		}
	})
}

// TestPropertySecureHandlerKeepsNonSensitiveValues checks the other side: a value
// under an ordinary key that matches no secret pattern reaches the log
// unchanged, so redaction does not hide what an operator needs to read.
func TestPropertySecureHandlerKeepsNonSensitiveValues(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		key := rapid.SampledFrom([]string{"url", "status", "host", "keyboard", "primary_key"}).Draw(t, "key")
		value := "v" + rapid.StringMatching(`[a-z]{1,8}`).Draw(t, "value")

		var buf bytes.Buffer
		NewSecureLogger(&buf, true).Info("event", key, value)

		want := fmt.Sprintf("%s=%s", key, value)
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("log %q does not contain %q", buf.String(), want)
		}
	})
}
