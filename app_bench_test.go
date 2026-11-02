package main

import (
	"fmt"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

func BenchmarkPrepareLoginJobs(b *testing.B) {
	for _, test := range []struct {
		entries, selected int
	}{
		{10, 1},
		{1000, 10},
		{10000, 100},
	} {
		b.Run(fmt.Sprintf("entries=%d/selected=%d", test.entries, test.selected), func(b *testing.B) {
			database := benchmarkDatabase(test.entries)
			teleports := make([]teleport, test.selected)
			for i := range teleports {
				teleports[i] = teleport{
					KeePassEntry: fmt.Sprintf("entry-%d", i),
					TOTPSource:   totpSourcePrompt,
				}
			}
			b.ReportAllocs()
			for b.Loop() {
				jobs, err := prepareLoginJobs(database, teleports)
				if err != nil {
					b.Fatal(err)
				}
				for i := range jobs {
					jobs[i].clear()
				}
			}
		})
	}
}

func benchmarkDatabase(count int) *gokeepasslib.Database {
	database := gokeepasslib.NewDatabase()
	entries := make([]gokeepasslib.Entry, count)
	for i := range entries {
		entries[i] = gokeepasslib.Entry{Values: []gokeepasslib.ValueData{
			{Key: "Title", Value: gokeepasslib.V{Content: fmt.Sprintf("entry-%d", i)}},
			{Key: "UserName", Value: gokeepasslib.V{Content: "fixture-user"}},
			{Key: "Password", Value: gokeepasslib.V{Content: "fixture-password", Protected: wrappers.NewBoolWrapper(true)}},
		}}
	}
	database.Content.Root.Groups = []gokeepasslib.Group{{Name: "Root", Entries: entries}}
	return database
}
