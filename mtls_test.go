package ngroklistener

import _ "embed"

//go:embed testdata/ngrok.ca.crt
var ngrokCA []byte
