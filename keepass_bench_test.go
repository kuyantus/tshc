package main

import "testing"

func BenchmarkParseTOTPSettings(b *testing.B) {
	for _, test := range []struct {
		name string
		uri  string
	}{
		{"defaults", "otpauth://totp/Teleport:alice?secret=JBSWY3DPEHPK3PXP"},
		{"custom", "otpauth://totp/Teleport:alice?secret=JBSWY3DPEHPK3PXP&issuer=Teleport&period=45&digits=8&algorithm=SHA256"},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				settings, err := parseTOTPSettings(test.uri)
				if err != nil {
					b.Fatal(err)
				}
				settings.clear()
			}
		})
	}
}
