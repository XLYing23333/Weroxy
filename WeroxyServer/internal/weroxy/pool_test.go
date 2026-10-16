package weroxy

import (
	"encoding/hex"
	"net"
	"strconv"
	"testing"
	"time"

	"weroxy/server/internal/legacy"
	"weroxy/server/internal/metrics"
	"weroxy/server/internal/policy"
	"weroxy/server/internal/ports"
	wp "weroxy/server/internal/protocol/weroxy"
	"weroxy/server/internal/secure"
)

func TestSharedListensOnlyOnAssignedPorts(t *testing.T) {
	secret := bytes32(8)
	tokenA, tokenB := bytes32(9), bytes32(10)
	uidA := hex.EncodeToString(bytes32(11)[:16])
	uidB := hex.EncodeToString(bytes32(12)[:16])
	dir := t.TempDir()
	echo := echoServer(t)
	pool := ports.Pool{First: 35200, Last: 35203, Reserved: 1}
	svc := New(Options{
		Devices: []Device{
			{ID: 1, Name: "a", UID: uidA, TokenMAC: legacy.MAC(secret, tokenA), Credential: secure.Derive(tokenA, "control")},
			{ID: 2, Name: "b", UID: uidB, TokenMAC: legacy.MAC(secret, tokenB), Credential: secure.Derive(tokenB, "control")},
		},
		Forwards: []Forward{
			{ID: 1, DeviceID: 1, Listen: "127.0.0.1:0", Target: echo},
			{ID: 2, DeviceID: 2, Listen: "127.0.0.1:0", Target: echo},
		},
		Pool: &pool, PoolHost: "127.0.0.1",
	})
	control, _, bound, err := svc.StartAllocated(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if svc.DataPorts() != 1 || len(bound) != 2 {
		t.Fatalf("data=%d forwards=%d", svc.DataPorts(), len(bound))
	}
	if !svc.PortOpen(35200) || svc.PortOpen(35201) || svc.PortOpen(35203) {
		t.Fatal("unassigned or reserved ports were listened")
	}
	conn, dialErr := net.DialTimeout("tcp", "127.0.0.1:35201", 200*time.Millisecond)
	if dialErr == nil {
		conn.Close()
		t.Fatal("unassigned data port accepted a connection")
	}
	clientA := authControl(t, control, dir, uidA, tokenA)
	clientB := authControl(t, control, dir, uidB, tokenB)
	openA := openVisitor(t, clientA, bound[0])
	openB := openVisitor(t, clientB, bound[1])
	if openA[2] != openB[2] || !hasPort(openA[2], 35200) {
		t.Fatalf("shared data=%s %s", openA[2], openB[2])
	}
}

func TestExclusiveQuotaRejectsAndDrainKeepsTheLiveSession(t *testing.T) {
	secret := bytes32(13)
	token := bytes32(14)
	uid := hex.EncodeToString(bytes32(15)[:16])
	dir := t.TempDir()
	echo := echoServer(t)
	pool := ports.Pool{First: 35300, Last: 35301, Reserved: 0}
	count := metrics.New()
	svc := New(Options{
		Count:   count,
		Devices: []Device{{ID: 1, Name: "box", UID: uid, TokenMAC: legacy.MAC(secret, token), Credential: secure.Derive(token, "control")}},
		Forwards: []Forward{
			{ID: 7, DeviceID: 1, Listen: "127.0.0.1:0", Target: echo, Mode: ports.Exclusive, Min: 1, Preferred: 2, Max: 2, Enabled: true},
			{ID: 8, DeviceID: 2, Listen: "127.0.0.1:0", Target: echo, Mode: ports.Exclusive, Min: 1, Preferred: 1, Max: 1, Enabled: true},
		},
		Pool: &pool, PoolHost: "127.0.0.1",
	})
	control, _, bound, err := svc.StartAllocated(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if len(bound) != 1 || svc.DataPorts() != 2 {
		t.Fatalf("bound=%d data=%d", len(bound), svc.DataPorts())
	}
	client := authControl(t, control, dir, uid, token)
	left := holdEcho(t, dir, uid, client, bound[0], echo, "left!")
	right := holdEcho(t, dir, uid, client, bound[0], echo, "right")
	if !hasPort(left.addr, 35300) || !hasPort(right.addr, 35301) {
		t.Fatalf("ports %s %s", left.addr, right.addr)
	}
	svc.Shrink(7, 1)
	if got := roundTrip(t, right.visitor, "still"); got != "still" {
		t.Fatalf("drained session=%q", got)
	}
	third := openVisitor(t, client, bound[0])
	if !hasPort(third[2], 35300) || hasPort(third[2], 35301) {
		t.Fatalf("new session data=%s", third[2])
	}
	right.close()
	waitPort(t, svc, 35301, false)
	if !svc.PortOpen(35300) {
		t.Fatal("serving port closed")
	}
	if got := roundTrip(t, left.visitor, "ok"); got != "ok" {
		t.Fatalf("serving session=%q", got)
	}
	snap := count.Snapshot()
	if snap.GlobalUp == 0 || snap.GlobalDown == 0 {
		t.Fatalf("bytes=%+v", snap)
	}
	layered := snap.DeviceUp[1] + snap.DeviceDown[1] + snap.ForwardUp[7] + snap.ForwardDown[7]
	if snap.GlobalUp+snap.GlobalDown == layered {
		t.Fatal("global total counted both layers")
	}
}

func TestAdmissionHappensBeforeOpenAndIgnoresControl(t *testing.T) {
	secret := bytes32(16)
	tokenA, tokenB := bytes32(17), bytes32(18)
	uidA := hex.EncodeToString(bytes32(19)[:16])
	uidB := hex.EncodeToString(bytes32(20)[:16])
	dir := t.TempDir()
	count := metrics.New()
	rules := &policy.Table{}
	rules.Replace(policy.Rule{}, map[string]policy.Rule{
		"alpha": {MaxPending: policy.Limit{Set: true, Value: 0}},
	}, nil)
	admit := policy.NewAdmission(8)
	svc := New(Options{
		Count: count, Admit: admit, Rules: rules,
		Devices: []Device{
			{ID: 1, Name: "alpha", UID: uidA, TokenMAC: legacy.MAC(secret, tokenA), Credential: secure.Derive(tokenA, "control")},
			{ID: 2, Name: "beta", UID: uidB, TokenMAC: legacy.MAC(secret, tokenB), Credential: secure.Derive(tokenB, "control")},
		},
		Forwards: []Forward{
			{ID: 1, DeviceID: 1, Listen: "127.0.0.1:0", Target: "127.0.0.1:9"},
			{ID: 2, DeviceID: 2, Listen: "127.0.0.1:0", Target: "127.0.0.1:9"},
		},
	})
	control, _, bound, err := svc.Start(t.Context(), "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	beta := authControl(t, control, dir, uidB, tokenB)
	alpha := authControl(t, control, dir, uidA, tokenA)
	visitor := dialTCP(t, bound[0])
	defer visitor.Close()
	_, _ = visitor.Write([]byte("x"))
	expectNoFrame(t, alpha)
	if count.Snapshot().Rejected[policy.ReasonPending] == 0 {
		t.Fatalf("rejected=%v", count.Snapshot().Rejected)
	}
	banned := mustNet(t, "127.0.0.1/32")
	admit.SetLimits([]policy.Ban{{Scope: "device", Key: "alpha", Net: banned}}, nil)
	rules.Replace(policy.Rule{MaxPerIP: policy.Limit{Set: true, Value: 1}}, nil, nil)
	echo := echoServer(t)
	held := holdEcho(t, dir, uidB, beta, bound[1], echo, "stay")
	rules.Replace(policy.Rule{MaxPerIP: policy.Limit{Set: true, Value: 0}}, nil, nil)
	if got := roundTrip(t, held.visitor, "more"); got != "more" {
		t.Fatalf("existing=%q", got)
	}
	again := dialTCP(t, bound[1])
	defer again.Close()
	_, _ = again.Write([]byte("n"))
	expectNoFrame(t, beta)
	if count.Snapshot().Rejected[policy.ReasonIP] == 0 {
		t.Fatalf("rejected=%v", count.Snapshot().Rejected)
	}
	bannedVisitor := dialTCP(t, bound[0])
	defer bannedVisitor.Close()
	_, _ = bannedVisitor.Write([]byte("b"))
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && count.Snapshot().Rejected[policy.ReasonBanned] == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if count.Snapshot().Rejected[policy.ReasonBanned] == 0 {
		t.Fatalf("rejected=%v", count.Snapshot().Rejected)
	}
}

type heldSession struct {
	visitor net.Conn
	data    net.Conn
	addr    string
}

func (h heldSession) close() {
	_ = h.visitor.Close()
	_ = h.data.Close()
}

func authControl(t *testing.T, addr, dir, uid string, token []byte) net.Conn {
	t.Helper()
	conn := dialTCP(t, addr)
	t.Cleanup(func() { conn.Close() })
	conn = writeHello(t, conn, token)
	frame := readFrame(t, conn)
	if frame.Type != wp.TypeWelcome {
		t.Fatalf("type=%d", frame.Type)
	}
	writeAuth(t, conn, uid, token)
	frame = readFrame(t, conn)
	if frame.Type != wp.TypeSync {
		t.Fatalf("type=%d", frame.Type)
	}
	return conn
}

func openVisitor(t *testing.T, control net.Conn, listen string) []string {
	t.Helper()
	visitor := dialTCP(t, listen)
	t.Cleanup(func() { visitor.Close() })
	if _, err := visitor.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	frame := readFrame(t, control)
	if frame.Type != wp.TypeOpen {
		t.Fatalf("type=%d", frame.Type)
	}
	parts, err := wp.Strings(frame.Body, 4)
	if err != nil {
		t.Fatal(err)
	}
	return parts
}

func holdEcho(t *testing.T, dir, uid string, control net.Conn, listen, echo, payload string) heldSession {
	t.Helper()
	visitor := dialTCP(t, listen)
	if _, err := visitor.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	frame := readFrame(t, control)
	if frame.Type != wp.TypeOpen {
		t.Fatalf("type=%d", frame.Type)
	}
	open, err := wp.Strings(frame.Body, 4)
	if err != nil {
		t.Fatal(err)
	}
	data := dialTCP(t, open[2])
	target := dialTCP(t, echo)
	bind, err := wp.PutStrings(open[3], uid, open[0], open[2])
	if err != nil {
		t.Fatal(err)
	}
	data = bindData(t, data, bind)
	if err := writeFrame(data, wp.Frame{Type: wp.TypeReady, RequestID: 2}); err != nil {
		t.Fatal(err)
	}
	ready := readFrame(t, data)
	if ready.Type != wp.TypeReady {
		t.Fatalf("type=%d", ready.Type)
	}
	_ = data.SetDeadline(time.Time{})
	_ = visitor.SetDeadline(time.Time{})
	_ = target.SetDeadline(time.Time{})
	go splice(target, data, nil, nil)
	if got := string(readN(t, visitor, len(payload))); got != payload {
		t.Fatalf("early=%q", got)
	}
	return heldSession{visitor: visitor, data: data, addr: open[2]}
}

func roundTrip(t *testing.T, conn net.Conn, payload string) string {
	t.Helper()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	return string(readN(t, conn, len(payload)))
}

func expectNoFrame(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := (wp.Reader{R: conn}).Next(); err == nil {
		t.Fatal("unexpected control frame")
	}
}

func hasPort(addr string, port int) bool {
	_, got, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	number, err := strconv.Atoi(got)
	return err == nil && number == port
}

func waitPort(t *testing.T, svc *Service, port int, open bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if svc.PortOpen(port) == open {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("port %d open=%v", port, svc.PortOpen(port))
}

func mustNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return network
}

func TestWildcardDataBindMatchesConcreteLocalPort(t *testing.T) {
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", rawPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	advertised := net.JoinHostPort("0.0.0.0", rawPort)
	if accepted.LocalAddr().String() == advertised {
		t.Fatal("test needs a concrete accepted local address")
	}
	newService := func() *Service {
		return &Service{
			devices:   []Device{{ID: 1, UID: "uid"}},
			dataPorts: []*dataPort{{port: port}},
			sessions: map[string]*session{"session": {
				id: "session", deviceID: 1, uid: "uid", dataAddr: advertised,
				port: port, ticket: "ticket", expires: time.Now().Add(time.Minute),
			}},
		}
	}
	body, err := wp.PutStrings("ticket", "uid", "session", advertised)
	if err != nil {
		t.Fatal(err)
	}
	frame := wp.Frame{Type: wp.TypeDataBind, Body: body}
	if sess, code := newService().consume(frame, accepted.LocalAddr().String()); sess == nil || code != 0 {
		t.Fatalf("wildcard bind rejected: code=%d", code)
	}
	if sess, code := newService().consume(frame, "127.0.0.1:1"); sess != nil || code != wp.CodeTicket {
		t.Fatalf("wrong local port accepted: code=%d", code)
	}
}

// Go may report a 0.0.0.0 listener as [::]; reload must reuse it.
func TestWildcardReloadAddsForwardAndPreservesLiveSession(t *testing.T) {
	probe, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	dataPort := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	secret, token := bytes32(41), bytes32(42)
	uid := hex.EncodeToString(bytes32(43)[:16])
	dir := t.TempDir()
	echo := echoServer(t)
	pool := ports.Pool{First: dataPort, Last: dataPort}
	svc := New(Options{Devices: []Device{{ID: 1, Name: "box", UID: uid, TokenMAC: legacy.MAC(secret, token), Credential: secure.Derive(token, "control")}},
		Forwards: []Forward{{ID: 1, DeviceID: 1, Listen: "0.0.0.0:0", Target: echo}},
		Pool:     &pool, PoolHost: "0.0.0.0"})
	control, _, bound, err := svc.StartAllocated(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client := authControl(t, control, dir, uid, token)
	held := holdEcho(t, dir, uid, client, bound[0], echo, "before")
	defer held.close()
	_, port, err := net.SplitHostPort(bound[0])
	if err != nil {
		t.Fatal(err)
	}
	desired := []Forward{
		{ID: 1, DeviceID: 1, Listen: net.JoinHostPort("0.0.0.0", port), Target: echo, Mode: ports.Shared, Min: 1, Preferred: 1, Max: 1, Enabled: true},
		{ID: 2, DeviceID: 1, Listen: "0.0.0.0:0", Target: echo, Mode: ports.Shared, Min: 1, Preferred: 1, Max: 1, Enabled: true},
	}
	assignments := []ports.Assignment{
		{ForwardID: 1, DeviceID: 1, Port: dataPort, State: ports.Serving},
		{ForwardID: 2, DeviceID: 1, Port: dataPort, State: ports.Serving},
	}
	if err := svc.ReconcileForwards(t.Context(), desired, assignments, &pool, "0.0.0.0"); err != nil {
		t.Fatal(err)
	}
	if got := roundTrip(t, held.visitor, "after"); got != "after" {
		t.Fatalf("existing session = %q", got)
	}
	snapshot := svc.SnapshotForwards()
	added := holdEcho(t, dir, uid, client, snapshot.Forwards[1].Listen, echo, "new")
	defer added.close()
	_, addedPort, _ := net.SplitHostPort(snapshot.Forwards[1].Listen)
	desired[1].Listen = net.JoinHostPort("0.0.0.0", addedPort)
	if err := svc.ReconcileForwards(t.Context(), desired, assignments, &pool, "0.0.0.0"); err != nil {
		t.Fatal(err)
	}
	if got := roundTrip(t, added.visitor, "again"); got != "again" {
		t.Fatalf("new session = %q", got)
	}
}

func TestSuccessfulHealthObservationsRespectCacheBudget(t *testing.T) {
	svc := New(Options{})
	for id := int64(1); id <= 10000; id++ {
		svc.reportPortSuccessLocked(id, 29100)
	}
	if len(svc.portHealth) > 4096 {
		t.Fatalf("health cache=%d", len(svc.portHealth))
	}
	svc.reportPortFailureLocked(1, 29100)
	svc.reportPortSuccessLocked(1, 29100)
	if svc.portHealth[portHealthKey{deviceID: 1, port: 29100}].success.IsZero() {
		t.Fatal("existing observation could not recover")
	}
}
