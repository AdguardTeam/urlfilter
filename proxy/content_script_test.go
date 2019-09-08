package proxy

import (
	"bytes"
	"testing"

	"github.com/AdguardTeam/golibs/log"

	"github.com/AdguardTeam/urlfilter"
)

func TestContentScriptTmpl(t *testing.T) {
	params := contentScriptParameters{
		Nonce: "test123",
		Result: urlfilter.CosmeticResult{
			ElementHiding: urlfilter.StylesResult{
				Generic: []string{
					"#generic_banner",
				},
				Specific: []string{
					"#specific_banner",
				},
				GenericExtCSS: []string{
					"#generic_extcss_banner",
				},
				SpecificExtCSS: []string{
					"#specific_extcss_banner",
				},
			},
			CSS: urlfilter.StylesResult{
				Generic: []string{
					"#generic_banner { visibility: none; content: \"test\"; }",
				},
				Specific: []string{
					"#specific_banner { visibility: none; content: \"test\"; }",
				},
				GenericExtCSS: []string{
					"#generic_extcss_banner { visibility: none; content: \"test\"; }",
				},
				SpecificExtCSS: []string{
					"#specific_extcss_banner { visibility: none; content: \"test\"; }",
				},
			},
			JS: urlfilter.ScriptsResult{
				Generic: []string{
					"console.log('hello from generic')",
				},
				Specific: []string{
					"console.log('hello from generic')",
				},
			},
		},
	}

	var data bytes.Buffer
	if err := contentScriptTmpl.Execute(&data, params); err != nil {
		t.Fatalf("could not execute template: %s", err)
	}

	log.Printf(data.String())

	// TODO: Run a nodejs script that will validate the data
}
