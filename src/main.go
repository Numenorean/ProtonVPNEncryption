package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"./srp"
)

var n = 1

const port = "6522"

func init() {
	defaultRoundTripper := http.DefaultTransport
	defaultTransportPtr, ok := defaultRoundTripper.(*http.Transport)
	if !ok {
		panic(fmt.Sprintf("defaultRoundTripper not an *http.Transport"))
	}
	defaultTransport := *defaultTransportPtr
	defaultTransport.MaxIdleConns = 25000
	defaultTransport.MaxIdleConnsPerHost = 25000
}

type authData struct {
	Username        string
	Password        string
	Modulus         string
	ServerEphemeral string
	Salt            string
}

func encrypt(username string, pwd string,
	ServerEphemeral string,
	Salt string, Modulus string) (string, string) {
	srpAuth, _ := srp.NewSrpAuth(4, username, pwd, Salt, Modulus, ServerEphemeral)
	proofs, _ := srpAuth.GenerateSrpProofs(2048)
	return base64.StdEncoding.EncodeToString(proofs.ClientEphemeral),
		base64.StdEncoding.EncodeToString(proofs.ClientProof)
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	var data authData
	_ = json.NewDecoder(r.Body).Decode(&data)
	ClientEphemeral, ClientProof := encrypt(data.Username, data.Password,
		data.ServerEphemeral, data.Salt,
		data.Modulus)
	fmt.Fprintf(w, "{\"ClientEphemeral\":\"%s\",\"ClientProof\":\"%s\"}", ClientEphemeral, ClientProof)
	fmt.Printf("\rRequest #%d", n)
	n++
}

func main() {
	fmt.Printf("Server's been started on %s port\n", port)
	http.HandleFunc("/encrypt", encryptHandler)
	http.ListenAndServe(":"+port, nil)
}
