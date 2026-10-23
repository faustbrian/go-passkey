//go:build integration && browser

package postgres

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// This complete owned journey uses a real isolated Chromium CTAP authenticator,
// not the handwritten test signer. Its localhost HTTP allowance is explicit
// test configuration; normal HTTPS/RP/origin checks are not disabled globally.
func TestBrowserNativePasskeyEnrollmentSigninAndLogout(t *testing.T) {
	f := newEnrollmentFixture(t)
	binary := os.Getenv("WEBAUTHN_BROWSER_BINARY")
	if binary == "" {
		t.Fatal("WEBAUTHN_BROWSER_BINARY required for selected browser interoperability")
	}
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<!doctype html><title>Passkey interoperability fixture</title>")
	}))
	defer web.Close()
	origin := strings.Replace(web.URL, "127.0.0.1", "localhost", 1)
	browser := startPasskeyBrowser(t, f.ctx, binary, origin)
	config := f.service.config()
	config.Protocol.RelyingParty.ID = "localhost"
	config.Protocol.RelyingParty.Origins = []string{origin}
	config.Protocol.DevelopmentLocalhostHTTP = true
	var err error
	f.service, err = NewEnrollmentService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	request := f.request(t, false)
	request.Origin = origin
	options, err := f.service.RegistrationOptions(f.ctx, request)
	if err != nil {
		t.Fatal("native browser registration options", err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("missing committed registration ceremony")
	}
	var wire json.RawMessage
	if err := options.TransferJSON(f.ctx, func(_ context.Context, p []byte) error { wire = bytes.Clone(p); return nil }); err != nil {
		t.Fatal(err)
	}
	response := browser.operation(t, "create", wire)
	clear(wire)
	completion := RegistrationCompletion{RegistrationRequest: f.request(t, true), CeremonyID: ceremony.ID, Response: response, Label: "Signin key"}
	completion.Origin = origin
	registered, err := f.service.Register(f.ctx, completion)
	clear(response)
	if err != nil {
		t.Fatal("real browser native enrollment", err)
	}
	credential, ok := registered.Credential()
	if !ok || credential.RPID != "localhost" {
		t.Fatal("missing verified browser credential")
	}
	login := newSigninFixtureForEnrolledAccount(t, f)
	r := login.request(t, session.BrowserSession)
	assertionOptions, err := login.signin.AuthenticationOptions(f.ctx, r)
	if err != nil {
		t.Fatal("native browser signin options", err)
	}
	assertionCeremony, ok := assertionOptions.Ceremony()
	if !ok {
		t.Fatal("missing committed assertion ceremony")
	}
	if err := assertionOptions.TransferJSON(f.ctx, func(_ context.Context, p []byte) error { wire = bytes.Clone(p); return nil }); err != nil {
		t.Fatal(err)
	}
	assertion := browser.operation(t, "get", wire)
	clear(wire)
	r.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	issued, err := login.signin.Signin(f.ctx, SigninCompletion{SigninRequest: r, CeremonyID: assertionCeremony.ID, Response: assertion})
	clear(assertion)
	if err != nil || issued.Session.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("real browser native signin", err)
	}
	passkeyJourneyReadInventoryLogout(t, login, issued)
}

type passkeyBrowserPipe struct {
	input   io.WriteCloser
	output  *bufio.Reader
	command *exec.Cmd
}

func (b *passkeyBrowserPipe) operation(t *testing.T, operation string, options json.RawMessage) json.RawMessage {
	t.Helper()
	if e := json.NewEncoder(b.input).Encode(struct {
		Operation string          `json:"operation"`
		Options   json.RawMessage `json:"options"`
	}{operation, options}); e != nil {
		t.Fatal("browser pipe write")
	}
	line, e := b.output.ReadBytes('\n')
	if e != nil {
		t.Fatal("browser pipe read")
	}
	if len(line) > 256<<10 {
		t.Fatal("browser response bound")
	}
	var response struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if json.Unmarshal(line, &response) != nil || response.Error != "" || len(response.Result) == 0 {
		t.Fatal("independent browser operation failed", response.Error)
	}
	return response.Result
}
func startPasskeyBrowser(t *testing.T, ctx context.Context, binary, origin string) *passkeyBrowserPipe {
	t.Helper()
	profile := t.TempDir()
	browserCtx, stopBrowser := context.WithCancel(ctx)
	chrome := exec.CommandContext(browserCtx, binary, "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--password-store=basic", "--use-mock-keychain", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0", "--user-data-dir="+profile, "about:blank")
	chrome.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	chrome.Stdout = io.Discard
	chrome.Stderr = io.Discard
	if e := chrome.Start(); e != nil {
		stopBrowser()
		t.Fatal("start isolated headless browser")
	}
	t.Cleanup(func() { stopBrowser(); _ = syscall.Kill(-chrome.Process.Pid, syscall.SIGTERM); _ = chrome.Wait() })
	var endpoint string
	// This installed Chromium's cold --version startup alone can exceed the
	// inherited 2.5s fixture bound. Poll the actual endpoint file for at most
	// 10s (still bounded by ctx), rather than assuming a fixed startup delay.
	for range 400 {
		wire, e := os.ReadFile(filepath.Join(profile, "DevToolsActivePort"))
		if e == nil {
			parts := strings.Split(strings.TrimSpace(string(wire)), "\n")
			if len(parts) == 2 {
				endpoint = "ws://127.0.0.1:" + parts[0] + parts[1]
				break
			}
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal("browser startup deadline")
		case <-timer.C:
		}
	}
	if endpoint == "" {
		t.Fatal("isolated browser did not expose loopback debugging endpoint")
	}
	node := exec.CommandContext(ctx, "node", "--input-type=module", "-e", passkeyBrowserDriver, endpoint, origin)
	node.Stderr = io.Discard
	input, e := node.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := node.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = node.Start(); e != nil {
		t.Fatal("start independent CDP driver")
	}
	b := &passkeyBrowserPipe{input: input, output: bufio.NewReaderSize(output, 256<<10), command: node}
	t.Cleanup(func() { _ = input.Close(); _ = node.Process.Kill(); _ = node.Wait() })
	line, e := b.output.ReadBytes('\n')
	if e != nil {
		t.Fatal("independent browser initialization failed")
	}
	var ready struct {
		Ready   bool   `json:"ready"`
		Version string `json:"version"`
		Driver  string `json:"driver"`
	}
	if json.Unmarshal(line, &ready) != nil || !ready.Ready {
		t.Fatal("independent browser not ready")
	}
	t.Logf("independent authenticator runtime: %s; driver %s", ready.Version, ready.Driver)
	return b
}

// Adapted from go-webauthn/postgres browser fixture at 693d54b (MIT).
// Real Chromium CTAP and native browser JSON conversion are independent of the
// handwritten signer. Credential payloads remain in pipes, never files/logs.
const passkeyBrowserDriver = `
import readline from 'node:readline';
const [endpoint, origin] = process.argv.slice(1);
const socket = new WebSocket(endpoint);
await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});
let next=0; const pending=new Map();
socket.addEventListener('message',event=>{const m=JSON.parse(event.data);if(m.id){const p=pending.get(m.id);if(p){pending.delete(m.id);m.error?p.reject(new Error('cdp-method-failed')):p.resolve(m.result);}}});
function send(method,params={},sessionId){const id=++next;return new Promise((resolve,reject)=>{pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});}
const version=await send('Browser.getVersion');
const {targetId}=await send('Target.createTarget',{url:origin});
const {sessionId}=await send('Target.attachToTarget',{targetId,flatten:true});
await send('Page.enable',{},sessionId);
await send('WebAuthn.enable',{enableUI:false},sessionId);
await send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',ctap2Version:'ctap2_1',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}},sessionId);
process.stdout.write(JSON.stringify({ready:true,version:version.product+' '+version.revision,driver:process.version})+'\n');
const lines=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
for await(const line of lines){try{
 const request=JSON.parse(line);if(!['create','get'].includes(request.operation))throw new Error('unsupported-operation');
 const method=request.operation==='create'?'parseCreationOptionsFromJSON':'parseRequestOptionsFromJSON';
 const expression='(async()=>{try{const input='+JSON.stringify(request.options)+';const options=PublicKeyCredential.'+method+'(input.publicKey);const credential=await navigator.credentials.'+request.operation+'({publicKey:options});return credential.toJSON();}catch(error){return {fixtureError:true};}})()';
 const evaluated=await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},sessionId);
 if(evaluated.exceptionDetails||evaluated.result.value?.fixtureError)throw new Error('browser-webauthn-failed');
 process.stdout.write(JSON.stringify({result:evaluated.result.value})+'\n');
 }catch(error){process.stdout.write(JSON.stringify({error:error.message})+'\n');}}
await send('Browser.close');socket.close();
`
