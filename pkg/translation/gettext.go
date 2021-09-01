package translation

import (
	"bufio"
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func Load(translations embed.FS, glob string) (*Translations, error) {
	filenames, err := fs.Glob(translations, glob)
	if err != nil {
		return nil, fmt.Errorf("glob match translation files: %w", err)
	}

	trans := Translations{
		locales: make(map[string]*Locale),
	}
	for _, filename := range filenames {
		b, err := fs.ReadFile(translations, filename)
		if err != nil {
			return nil, fmt.Errorf("read %q translation file: %w", filename, err)
		}
		language, pluralFn, messages, err := parsePO(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("parse %q translations file: %w", filename, err)
		}
		lang, ok := trans.locales[language]
		if !ok {
			lang = &Locale{
				plural:       pluralFn,
				translations: make(map[string][]string),
			}
			trans.locales[language] = lang
		}
		for _, m := range messages {
			lang.translations[m.id] = m.str
		}
	}

	if len(trans.locales) == 0 {
		return nil, errors.New("no translations files found")
	}

	return &trans, nil
}

// parsePO reads PO file and returns information required to translate
// messages.
//
// https://www.gnu.org/software/gettext/manual/html_node/PO-Files.html
func parsePO(po io.Reader) (language string, pluralFn func(int) int, messages []*gettextmsg, err error) {
	rd := bufio.NewReader(po)

	var lineno int
parseHeader:
	for ; ; lineno++ {
		line, err := rd.ReadString('\n')
		switch {
		case err == nil:
			// All good.
		case errors.Is(err, io.EOF) && line != "":
			// Last line.
		case errors.Is(err, io.EOF) && line == "":
			return language, pluralFn, messages, nil
		default:
			return "", nil, nil, fmt.Errorf("line %d: read line: %w", lineno, err)
		}
		switch {
		case line == "msgid \"\"\n":
		case line == "msgstr \"\"\n":
		case strings.HasPrefix(line, `msgid "`):
		case pluralFn != nil && language != "" && strings.TrimSpace(line) == "":
			break parseHeader
		case strings.HasPrefix(line, "# "):
			// This is a comment that can be ignored.
		case strings.HasPrefix(line, "\"Plural-Forms: "):
			code := unquote(line)[14:]
			fn, err := compilePluralFn(code)
			if err != nil {
				return "", nil, nil, fmt.Errorf("compile plural function code: %w", err)
			}
			pluralFn = fn
		case strings.HasPrefix(line, "\"Language: "):
			language = unquote(unquote(line)[10:])
		default:
			// Ignore.
		}
	}

	current := &gettextmsg{}
	// For support of multiline strings, keep track of which attribute is
	// being parsed.
	var laststr *string = nil

	for ; ; lineno++ {
		line, err := rd.ReadString('\n')
		switch {
		case err == nil:
			// All good.
		case errors.Is(err, io.EOF) && line != "":
			// Last line.
		case errors.Is(err, io.EOF) && line == "":
			if current.id != "" {
				messages = append(messages, current)
			}
			return language, pluralFn, messages, nil
		default:
			return "", nil, nil, fmt.Errorf("line %d: read line: %w", lineno, err)
		}

		switch {
		case strings.HasPrefix(line, "# "):
			// This is a comment that can be ignored.
			continue
		case strings.TrimSpace(line) == "":
			if current.id != "" {
				messages = append(messages, current)
			}
			laststr = nil
			current = &gettextmsg{}
		case strings.HasPrefix(line, "msgid "):
			if current.id != "" {
				laststr = nil
				messages = append(messages, current)
				current = &gettextmsg{}
			}
			current.id = unquote(line[6:])
			laststr = &current.id
		case strings.HasPrefix(line, "msgid_plural "):
			current.plural = unquote(line[13:])
			laststr = &current.plural
		case strings.HasPrefix(line, "msgstr "):
			current.str = append(current.str, unquote(line[7:]))
			laststr = &current.str[len(current.str)-1]
		case strings.HasPrefix(line, "msgstr["):
			line = line[7:]

			var index int
			for i, c := range line {
				if c != ']' {
					continue
				}
				index, err = strconv.Atoi(line[:i])
				if err != nil {
					return "", nil, nil, fmt.Errorf("line %d: parse msgstr index %q: %w", lineno, line[:i], err)
				}
				line = line[i+2:]
			}

			for len(current.str) <= index {
				current.str = append(current.str, "")
			}
			current.str[index] = unquote(line)
			laststr = &current.str[index]
		case strings.HasPrefix(line, "\""):
			if laststr == nil {
				return "", nil, nil, fmt.Errorf("line %d: continuation of an unknown string", lineno)
			}
			*laststr += "\n" + unquote(line)
		case strings.HasPrefix(line, "#: "):
			current.sources = append(current.sources, strings.Fields(unquote(line[3:]))...)
		case strings.HasPrefix(line, "#. "):
			current.comment += strings.TrimSpace(line[3:])

		default:
			// Other cases are ignored - this line content is
			// nothing interesting to the translator.
		}
	}
}

type gettextmsg struct {
	id      string
	plural  string
	str     []string
	sources []string
	comment string
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if result, err := strconv.Unquote(s); err == nil {
		return result
	}
	return s
}

type Translations struct {
	locales map[string]*Locale
}

func (t Translations) Bind(language string) *Locale {
	// Nil Locale is a valid value. It does not translate anything,
	// but it won't cause any problems.
	return t.locales[language]
}

// Locale provides translations for a single language.
type Locale struct {
	translations map[string][]string
	plural       func(int) int
}

// T returns translation for a simple string.
func (lo *Locale) T(s string) string {
	if lo == nil {
		return s
	}
	if trans := lo.translations[s]; len(trans) > 0 {
		if t := trans[0]; t != "" {
			return t
		}
	}
	// If translation does not exist, fallback to the original message.
	return s
}

// Tn provides translation for a string, depending on the n argument which is
// used to determine which plural form to use.
func (lo *Locale) Tn(singular, plural string, n int) string {
	if lo != nil {
		if trans := lo.translations[singular]; len(trans) > 0 {
			index := lo.plural(n)
			if index < len(trans) && trans[index] != "" {
				return fmt.Sprintf(trans[index], n)
			}
		}
	}
	// If translation does not exist, fallback to the original message.
	if n == 1 {
		return fmt.Sprintf(singular, n)
	}
	return fmt.Sprintf(plural, n)
}

func compilePluralFn(gettextCode string) (func(int) int, error) {
	code := removeWhitespace(gettextCode)
	code = strings.TrimRight(code, ";\\n")
	fn, ok := pluralFuncs[code]
	if !ok {
		return nil, fmt.Errorf("plural function not not implemented: %q", code)
	}
	return fn, nil
}

// A collection of all plural functions. Instead of compiling the original
// code, use string matching to provide the equivalent in code. This simplified
// approach is possible, because plural function code is always generated in
// the same form.
// It is easier and faster to do a string matching than implement a VM.
var pluralFuncs = map[string]func(int) int{
	"nplurals=2;plural=(n!=1)": func(n int) int {
		if n != 1 {
			return 1
		}
		return 0
	},
	"nplurals=2;plural=(n>1);": func(n int) int {
		if n > 1 {
			return 1
		}
		return 0
	},
	"nplurals=4;plural=(n==1?0:(n%10>=2&&n%10<=4)&&(n%100<12||n%100>14)?1:n!=1&&(n%10>=0&&n%10<=1)||(n%10>=5&&n%10<=9)||(n%100>=12&&n%100<=14)?2:3);": func(n int) int {
		if n == 1 {
			return 0
		}
		if (n%10 >= 2 && n%10 <= 4) && (n%100 < 12 || n%100 > 14) {
			return 1
		}
		if n != 1 && (n%10 >= 0 && n%10 <= 1) || (n%10 >= 5 && n%10 <= 9) || (n%100 >= 12 && n%100 <= 14) {
			return 2
		}
		return 3
	},
	"nplurals=4;plural=((n%10==1&&n%100!=11)?0:((n%10>=2&&n%10<=4&&(n%100<12||n%100>14))?1:((n%10==0||(n%10>=5&&n%10<=9))||(n%100>=11&&n%100<=14))?2:3));": func(n int) int {
		if n%10 == 1 && n%100 != 11 {
			return 0
		}
		if n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14) {
			return 1
		}
		if (n%10 == 0 || (n%10 >= 5 && n%10 <= 9)) || (n%100 >= 11 && n%100 <= 14) {
			return 2
		}
		return 3
	},
	"nplurals=3;plural=n==1?0:n%10>=2&&n%10<=4&&(n%100<10||n%100>=20)?1:2": func(n int) int {
		if n == 1 {
			return 0
		}
		if n%10 >= 2 && n%10 <= 4 && (n%100 < 10 || n%100 >= 20) {
			return 1
		}
		return 2
	},
	"nplurals=1;plural=0;": func(n int) int {
		return 0
	},
	"nplurals=3;plural=(n==1?0:n%10>=2&&n%10<=4&&(n%100<12||n%100>14)?1:2)": func(n int) int {
		if n == 1 {
			return 0
		}
		if n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14) {
			return 1
		}
		return 2
	},
}

func createPo(messages []*gettextmsg) io.Reader {
	var (
		buf bytes.Buffer
		err error
	)

	writeln := func(format string, args ...interface{}) {
		if err != nil {
			return
		}
		if !strings.HasSuffix(format, "\n") {
			format += "\n"
		}
		if _, e := fmt.Fprintf(&buf, format, args...); e != nil {
			err = fmt.Errorf("writeln: %w", err)
		}
	}

	writeln(`msgid ""`)
	writeln(`msgstr ""`)
	writeln(``)
	writeln(`"MIME-Version: 1.0\n"`)
	writeln(`"Project-Id-Version: \n"`)
	writeln(`"Last-Translator: \n"`)
	writeln(`"Language: en\n"`)
	writeln(`"Content-Type: text/plain; charset=UTF-8\n"`)
	writeln(`"Plural-Forms: nplurals=2; plural=(n != 1);\n"`)
	writeln(`"PO-Revision-Date: %s\n"`, time.Now().Format("2006-01-02 15:04"))
	// Poedit requires source language information in order to provide
	// extra functionality.
	writeln(`"X-Source-Language: en\n"`)

	messages = cleanupMessages(messages)

	for _, m := range messages {
		writeln(``)
		if m.comment != "" {
			writeln(`#. %s`, m.comment)
		}
		if len(m.sources) > 0 {
			sort.Strings(m.sources)
			for _, s := range m.sources {
				writeln(`#: ` + s)
			}
		}
		writeln(`msgid %q`, m.id)
		if m.plural != "" {
			writeln(`msgid_plural %q`, m.plural)
		}
		switch len(m.str) {
		case 0:
			writeln(`msgstr ""`)
		case 1:
			writeln(`msgstr %q`, m.str[0])
		default:
			for i, msg := range m.str {
				writeln(`msgstr[%d] %q`, i, msg)
			}
		}
	}

	if err != nil {
		return errreader{err: err}
	}
	return &buf
}

func cleanupMessages(msgs []*gettextmsg) []*gettextmsg {
	// Build index in order to merge duplicates.
	index := make(map[string]*gettextmsg)
	for _, m := range msgs {
		msg, ok := index[m.id]
		if !ok {
			index[m.id] = m
			continue
		}
		msg.sources = append(msg.sources, m.sources...)

		// Naive rewrite.
		if len(msg.str) == 0 {
			msg.str = m.str
		}

		switch {
		case m.comment == "" && msg.comment == "":
			// Ignore.
		case m.comment != "" && msg.comment != "":
			msg.comment += "\n" + m.comment
		case m.comment != "" && msg.comment == "":
			msg.comment = m.comment
		case m.comment == "" && msg.comment != "":
			// Ingore.
		}
	}

	messages := make([]*gettextmsg, 0, len(index))
	for _, m := range index {
		messages = append(messages, m)
	}

	sort.Slice(messages, func(i, j int) bool {
		return messages[i].id < messages[j].id
	})

	return messages
}

type errreader struct{ err error }

func (r errreader) Read([]byte) (int, error) { return 0, r.err }

func PoFromGo(filename string, code io.Reader) io.Reader {
	messages, err := messagesFromGo(filename, code)
	if err != nil {
		return errreader{err: fmt.Errorf("parse Go code: %w", err)}
	}
	return createPo(messages)

}

func messagesFromGo(filename string, html io.Reader) ([]*gettextmsg, error) {
	rd := bufio.NewReader(html)
	var messages []*gettextmsg

	tRx := regexp.MustCompile(`trans\.T\("([^"]*)"\)`)
	tnRx := regexp.MustCompile(`trans\.Tn\("([^"]*)", "([^"]*)", ([^)]+)\)`)

	for lineno := 0; ; lineno++ {
		line, err := rd.ReadString('\n')
		switch {
		case err == nil:
			// All good.
		case errors.Is(err, io.EOF) && line != "":
			// Last line.
		case errors.Is(err, io.EOF) && line == "":
			return messages, nil
		default:
			return nil, fmt.Errorf("line %d: read line: %w", lineno, err)
		}

		for _, match := range tRx.FindAllStringSubmatch(line, -1) {
			messages = append(messages, &gettextmsg{
				id:      unquote(match[1]),
				sources: []string{fmt.Sprintf("%s:%d", filename, lineno)},
			})
		}
		for _, match := range tnRx.FindAllStringSubmatch(line, -1) {
			messages = append(messages, &gettextmsg{
				id:      unquote(match[1]),
				plural:  unquote(match[2]),
				sources: []string{fmt.Sprintf("%s:%d", filename, lineno)},
				comment: fmt.Sprintf("Variable name: %s", match[3]),
			})
		}
	}
}

// PoFromHTML extracts all translation messages from the HTML template.
// Template is expected to use Go stdlib template engine with {{ and }} for
// blocks. Translation function must be called "translate" and contain either
// one or three arguments.
func PoFromHTML(filename string, html io.Reader) io.Reader {
	messages, err := messagesFromHTML(filename, html)
	if err != nil {
		return errreader{err: fmt.Errorf("parse HTML: %w", err)}
	}
	return createPo(messages)
}

func messagesFromHTML(filename string, html io.Reader) ([]*gettextmsg, error) {
	rd := bufio.NewReader(html)
	var messages []*gettextmsg

	translationFnRx := regexp.MustCompile(removeWhitespace(`
		{{
			\s*
			translate
			\s+
			("[^"]*")
			\s*
			("[^"]*")?
			\s*
			(\S*)?
			\s*
		}}
	`))

	for lineno := 0; ; lineno++ {
		line, err := rd.ReadString('\n')
		switch {
		case err == nil:
			// All good.
		case errors.Is(err, io.EOF) && line != "":
			// Last line.
		case errors.Is(err, io.EOF) && line == "":
			return messages, nil
		default:
			return nil, fmt.Errorf("line %d: read line: %w", lineno, err)
		}

		for _, match := range translationFnRx.FindAllStringSubmatch(line, -1) {
			switch {
			case match[1] == "":
				return nil, fmt.Errorf("line %d: empty translation string", lineno)
			case match[2] == "" && match[3] != "":
				return nil, fmt.Errorf("line %d: empty plural translation string", lineno)
			case match[2] == "" && match[3] == "":
				messages = append(messages, &gettextmsg{
					id:      unquote(match[1]),
					sources: []string{fmt.Sprintf("%s:%d", filename, lineno)},
				})
			case match[2] != "" && match[3] != "":
				messages = append(messages, &gettextmsg{
					id:      unquote(match[1]),
					plural:  unquote(match[2]),
					sources: []string{fmt.Sprintf("%s:%d", filename, lineno)},
					comment: fmt.Sprintf("Variable name: %s", match[3]),
				})
			}
		}
	}
}

func removeWhitespace(s string) string {
	return regexp.MustCompile(`\s+`).ReplaceAllString(s, "")
}

func MergePoFiles(poFiles ...io.Reader) io.Reader {
	switch len(poFiles) {
	case 0:
		return errreader{err: io.EOF}
	case 1:
		return poFiles[0]
	}

	lang, _, messages, err := parsePO(poFiles[0])
	if err != nil {
		return errreader{err: fmt.Errorf("parse 0 PO file: %w", err)}
	}
	if lang != "en" {
		return errreader{err: errors.New("parse 0 PO file: only en language files can be merged")}
	}

	for i, rd := range poFiles[1:] {
		lang, _, msgs, err := parsePO(rd)
		if err != nil {
			return errreader{err: fmt.Errorf("parse %d PO file: %w", i+1, err)}
		}
		if lang != "en" {
			return errreader{err: fmt.Errorf("parse %d PO file: only en language files can be merged", i+1)}
		}
		messages = append(messages, msgs...)
	}

	messages = cleanupMessages(messages)
	return createPo(messages)
}
