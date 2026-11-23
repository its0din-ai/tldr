package scanner

import "testing"

func TestParseWHOIS(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{
			name: "not found",
			text: "Domain not found.\n>>> Last update of WHOIS database\n",
			want: "available",
		},
		{
			name: "registered",
			text: "Domain Name: EXAMPLE.COM\nRegistry Domain ID: 123\nCreation Date: 1995-08-14\n",
			want: "taken",
		},
		{
			name: "unknown",
			text: "please try again later",
			want: "unknown",
		},
		{
			name: "rate limited",
			text: "query rate limit exceeded",
			want: "unknown",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, _ := parseWHOIS(test.text)
			if status != test.want {
				t.Errorf("parseWHOIS() = %q, want %q", status, test.want)
			}
		})
	}
}

func TestParseWhoisServer(t *testing.T) {
	text := "domain: io\nwhois: whois.nic.io\nstatus: ACTIVE\n"
	if got := parseWhoisServer(text); got != "whois.nic.io" {
		t.Errorf("parseWhoisServer() = %q, want whois.nic.io", got)
	}
	if got := parseWhoisServer("whois: whois.iana.org\n"); got != "" {
		t.Errorf("parseWhoisServer() = %q, want empty string", got)
	}
}
