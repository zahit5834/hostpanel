package sites

import "testing"

func TestChannelAndNewer(t *testing.T) {
	if Channel("dotnet-releases", "10.0.14") != "10.0" || Channel("node-dist", "24.11.1") != "24" || Channel("", "1.2.3") != "" {
		t.Fatal("channel")
	}
	if !newer("10.0.15", "10.0.9") || newer("10.0.9", "10.0.15") || newer("1.2.3", "1.2.3") {
		t.Fatal("newer")
	}
}
