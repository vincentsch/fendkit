package demo

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
)

//go:generate go run ./generate
//go:embed all:data
var assets embed.FS

//go:embed answers.yml
var answers string

func Copy(out string) error {
	tree, err := fs.Sub(assets, "data")
	if err != nil {
		return err
	}
	return os.CopyFS(out, tree)
}

func Answers(today time.Time) []byte {
	// Clamp leap day to February's last day in the target year.
	year, month, day := today.Date()
	end := time.Date(year+5, month, day, 0, 0, 0, 0, time.UTC)
	if end.Month() != month {
		end = end.AddDate(0, 0, -end.Day())
	}
	return []byte(strings.ReplaceAll(answers, "{{support_end}}", end.Format("2006-01-02")))
}

func ValidateOutput(out string) error {
	entries, err := os.ReadDir(out)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot read --out; choose a writable folder")
	}
	if len(entries) != 0 {
		return fmt.Errorf("--out is not empty; choose another folder with --out")
	}
	return nil
}
