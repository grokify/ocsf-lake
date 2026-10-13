package seed

import (
	"fmt"
	"math/rand"

	"github.com/grokify/ocsf-schema-go/ocsf/events"
	"github.com/grokify/ocsf-schema-go/ocsf/objects"
)

// Value pools for realistic-looking data. Names and addresses are
// placeholders, not real entities.
var (
	poolUsers     = []string{"amara.okafor", "li.wei", "sofia.marino", "dev.patel", "jonas.berg", "maya.haddad", "svc-backup", "svc-etl"}
	poolHostnames = []string{"web-01.corp.example.com", "db-02.corp.example.com", "jump-01.corp.example.com", "laptop-4821.corp.example.com", "build-07.corp.example.com"}
	poolIPs       = []string{"10.0.1.15", "10.0.2.33", "10.0.4.7", "192.168.10.24", "172.16.3.9", "10.0.5.101"}
	poolExtIPs    = []string{"203.0.113.10", "198.51.100.44", "192.0.2.199", "203.0.113.77"}
	poolProcs     = []struct{ name, path string }{
		{"chrome", "/opt/google/chrome/chrome"},
		{"sshd", "/usr/sbin/sshd"},
		{"python3", "/usr/bin/python3"},
		{"powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
		{"nginx", "/usr/sbin/nginx"},
	}
	poolFiles = []struct {
		name, path string
		typeID     int
	}{
		{"report-q3.xlsx", "/examplepath/finance/report-q3.xlsx", objects.FileTypeIDRegularFile},
		{"id_ed25519", "/examplepath/.ssh/id_ed25519", objects.FileTypeIDRegularFile},
		{"payload.dll", "C:\\examplepath\\payload.dll", objects.FileTypeIDRegularFile},
		{"backup.tar.gz", "/examplepath/backups/backup.tar.gz", objects.FileTypeIDRegularFile},
	}
	poolDomains = []string{"example.com", "cdn.example.net", "updates.example.org", "mail.example.com"}
	poolURLs    = []string{"/api/v1/login", "/static/app.js", "/admin/export", "/health"}
	poolRegKeys = []string{
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Sysmon64",
		"HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command",
	}
	poolFindings = []string{"Possible credential dumping", "Anomalous outbound transfer", "Suspicious scheduled task", "Brute-force pattern detected"}
)

// severityFor picks a weighted severity: mostly informational, few critical.
func severityFor(rng *rand.Rand) int {
	switch v := rng.Intn(100); {
	case v < 55:
		return events.SeverityIDInformational
	case v < 75:
		return events.SeverityIDLow
	case v < 88:
		return events.SeverityIDMedium
	case v < 96:
		return events.SeverityIDHigh
	default:
		return events.SeverityIDCritical
	}
}

func pick[T any](rng *rand.Rand, pool []T) T { return pool[rng.Intn(len(pool))] }

func metadataFor(uid, source string) *objects.Metadata {
	return &objects.Metadata{
		UID:     uid,
		Version: "1.10.0",
		Product: &objects.Product{Name: source, VendorName: "Example Corp"},
	}
}

func deviceFor(rng *rand.Rand) *objects.Device {
	return &objects.Device{
		TypeID:   objects.DeviceTypeIDServer,
		Hostname: pick(rng, poolHostnames),
		IP:       pick(rng, poolIPs),
	}
}

func actorFor(rng *rand.Rand) *objects.Actor {
	proc := pick(rng, poolProcs)
	return &objects.Actor{
		User:    &objects.User{Name: pick(rng, poolUsers), TypeID: objects.UserTypeIDUser},
		Process: &objects.Process{Name: proc.name, PID: 1000 + rng.Intn(60000)},
	}
}

// template builds one typed event. uid is the metadata.uid; source names the
// producing product.
type template func(rng *rand.Rand, uid, source string, timeMS int64) any

// templates maps class names to generators. Every template fills the class's
// required attributes and constraints so events pass strict validation.
var templates = map[string]template{
	"authentication":        authenticationTemplate,
	"file_activity":         fileActivityTemplate,
	"process_activity":      processActivityTemplate,
	"network_activity":      networkActivityTemplate,
	"dns_activity":          dnsActivityTemplate,
	"http_activity":         httpActivityTemplate,
	"detection_finding":     detectionFindingTemplate,
	"registry_key_activity": registryKeyActivityTemplate,
}

// classWeights drives the event mix; weights are relative.
var classWeights = []struct {
	name   string
	weight int
}{
	{"authentication", 25},
	{"network_activity", 20},
	{"dns_activity", 15},
	{"http_activity", 10},
	{"file_activity", 10},
	{"process_activity", 10},
	{"detection_finding", 5},
	{"registry_key_activity", 5},
}

func pickClass(rng *rand.Rand, allowed map[string]bool) string {
	total := 0
	for _, cw := range classWeights {
		if len(allowed) == 0 || allowed[cw.name] {
			total += cw.weight
		}
	}
	v := rng.Intn(total)
	for _, cw := range classWeights {
		if len(allowed) > 0 && !allowed[cw.name] {
			continue
		}
		if v < cw.weight {
			return cw.name
		}
		v -= cw.weight
	}
	return classWeights[0].name
}

func authenticationTemplate(rng *rand.Rand, uid, source string, timeMS int64) any {
	activity := events.AuthenticationActivityIDLogon
	if rng.Intn(5) == 0 {
		activity = events.AuthenticationActivityIDLogoff
	}
	statusID := events.StatusIDSuccess
	if rng.Intn(100) < 15 {
		statusID = events.StatusIDFailure
	}
	user := pick(rng, poolUsers)
	return events.Authentication{
		ActivityID:  activity,
		CategoryUID: events.CategoryUIDIAM,
		ClassUID:    events.ClassUIDAuthentication,
		TypeUID:     int64(events.ClassUIDAuthentication*100 + activity),
		SeverityID:  severityFor(rng),
		StatusID:    statusID,
		Time:        timeMS,
		Metadata:    metadataFor(uid, source),
		User:        &objects.User{Name: user, TypeID: objects.UserTypeIDUser},
		DstEndpoint: &objects.NetworkEndpoint{Hostname: pick(rng, poolHostnames)},
		SrcEndpoint: &objects.NetworkEndpoint{IP: pick(rng, poolIPs)},
		Message:     fmt.Sprintf("User %s authentication", user),
	}
}

func fileActivityTemplate(rng *rand.Rand, uid, source string, timeMS int64) any {
	f := pick(rng, poolFiles)
	activity := 1 + rng.Intn(2) // Create / Read
	return events.FileActivity{
		ActivityID:  activity,
		CategoryUID: events.CategoryUIDSystem,
		ClassUID:    events.ClassUIDFileActivity,
		TypeUID:     int64(events.ClassUIDFileActivity*100 + activity),
		SeverityID:  severityFor(rng),
		Time:        timeMS,
		Metadata:    metadataFor(uid, source),
		Actor:       actorFor(rng),
		Device:      deviceFor(rng),
		File:        &objects.File{Name: f.name, Path: f.path, TypeID: f.typeID},
	}
}

func processActivityTemplate(rng *rand.Rand, uid, source string, timeMS int64) any {
	proc := pick(rng, poolProcs)
	activity := 1 // Launch
	return events.ProcessActivity{
		ActivityID:  activity,
		CategoryUID: events.CategoryUIDSystem,
		ClassUID:    events.ClassUIDProcessActivity,
		TypeUID:     int64(events.ClassUIDProcessActivity*100 + activity),
		SeverityID:  severityFor(rng),
		Time:        timeMS,
		Metadata:    metadataFor(uid, source),
		Actor:       actorFor(rng),
		Device:      deviceFor(rng),
		Process: &objects.Process{
			Name:    proc.name,
			PID:     1000 + rng.Intn(60000),
			CmdLine: proc.path,
		},
	}
}

func networkActivityTemplate(rng *rand.Rand, uid, source string, timeMS int64) any {
	activity := 1 + rng.Intn(2) // Open / Close
	return events.NetworkActivity{
		ActivityID:  activity,
		CategoryUID: events.CategoryUIDNetwork,
		ClassUID:    events.ClassUIDNetworkActivity,
		TypeUID:     int64(events.ClassUIDNetworkActivity*100 + activity),
		SeverityID:  severityFor(rng),
		Time:        timeMS,
		Metadata:    metadataFor(uid, source),
		SrcEndpoint: &objects.NetworkEndpoint{IP: pick(rng, poolIPs), Port: 30000 + rng.Intn(30000)},
		DstEndpoint: &objects.NetworkEndpoint{IP: pick(rng, poolExtIPs), Port: 443},
	}
}

func dnsActivityTemplate(rng *rand.Rand, uid, source string, timeMS int64) any {
	activity := 1 // Query
	return events.DNSActivity{
		ActivityID:  activity,
		CategoryUID: events.CategoryUIDNetwork,
		ClassUID:    events.ClassUIDDNSActivity,
		TypeUID:     int64(events.ClassUIDDNSActivity*100 + activity),
		SeverityID:  severityFor(rng),
		Time:        timeMS,
		Metadata:    metadataFor(uid, source),
		SrcEndpoint: &objects.NetworkEndpoint{IP: pick(rng, poolIPs)},
		Query:       &objects.DNSQuery{Hostname: pick(rng, poolDomains)},
	}
}

func httpActivityTemplate(rng *rand.Rand, uid, source string, timeMS int64) any {
	activity := 1 + rng.Intn(4)
	return events.HTTPActivity{
		ActivityID:  activity,
		CategoryUID: events.CategoryUIDNetwork,
		ClassUID:    events.ClassUIDHTTPActivity,
		TypeUID:     int64(events.ClassUIDHTTPActivity*100 + activity),
		SeverityID:  severityFor(rng),
		Time:        timeMS,
		Metadata:    metadataFor(uid, source),
		HTTPRequest: &objects.HTTPRequest{
			URL:        &objects.URL{Path: pick(rng, poolURLs), Hostname: pick(rng, poolDomains)},
			HTTPMethod: pick(rng, []string{"GET", "POST", "GET", "GET"}),
		},
	}
}

func detectionFindingTemplate(rng *rand.Rand, uid, source string, timeMS int64) any {
	activity := 1 // Create
	return events.DetectionFinding{
		ActivityID:  activity,
		CategoryUID: events.CategoryUIDFindings,
		ClassUID:    events.ClassUIDDetectionFinding,
		TypeUID:     int64(events.ClassUIDDetectionFinding*100 + activity),
		SeverityID:  severityFor(rng),
		Time:        timeMS,
		Metadata:    metadataFor(uid, source),
		FindingInfo: &objects.FindingInfo{
			UID:   "finding-" + uid,
			Title: pick(rng, poolFindings),
		},
	}
}

func registryKeyActivityTemplate(rng *rand.Rand, uid, source string, timeMS int64) any {
	activity := 1 + rng.Intn(3) // Create / Read / Modify
	return events.RegistryKeyActivity{
		ActivityID:  activity,
		CategoryUID: events.CategoryUIDSystem,
		ClassUID:    events.ClassUIDRegistryKeyActivity,
		TypeUID:     int64(events.ClassUIDRegistryKeyActivity*100 + activity),
		SeverityID:  severityFor(rng),
		Time:        timeMS,
		Metadata:    metadataFor(uid, source),
		Actor:       actorFor(rng),
		Device:      deviceFor(rng),
		RegKey:      &objects.RegKey{Path: pick(rng, poolRegKeys)},
	}
}
