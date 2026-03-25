package main

import (
	"fmt"
	"os"

	_ "github.com/akesondr/akeso-ndr/internal/api"
	_ "github.com/akesondr/akeso-ndr/internal/capture"
	_ "github.com/akesondr/akeso-ndr/internal/common"
	_ "github.com/akesondr/akeso-ndr/internal/config"
	_ "github.com/akesondr/akeso-ndr/internal/detect"
	_ "github.com/akesondr/akeso-ndr/internal/export"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/dcerpc"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/dns"
	ndrhttp "github.com/akesondr/akeso-ndr/internal/protocols/http"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/kerberos"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/ldap"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/ntlm"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/rdp"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/smb"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/smtp"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/ssh"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/tls"
	_ "github.com/akesondr/akeso-ndr/internal/sessions"
	_ "github.com/akesondr/akeso-ndr/internal/signatures"
)

// Blank import to verify all packages compile.
var _ = ndrhttp.Placeholder

func main() {
	fmt.Println("AkesoNDR — Network Detection & Response")
	fmt.Println("AkesoNDR POC v0.1.0")
	os.Exit(0)
}
