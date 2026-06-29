package ocsf

// Category UIDs as defined by OCSF v1.3.0
const (
	CategoryUIDSystemActivity      = 1
	CategoryUIDFindingsActivity    = 2
	CategoryUIDIAMActivity         = 3
	CategoryUIDNetworkActivity     = 4
	CategoryUIDDiscovery           = 5
	CategoryUIDApplicationActivity = 6
)

// CategoryName returns the human-readable name for a category UID.
func CategoryName(uid int) string {
	switch uid {
	case CategoryUIDSystemActivity:
		return "System Activity"
	case CategoryUIDFindingsActivity:
		return "Findings"
	case CategoryUIDIAMActivity:
		return "Identity & Access Management"
	case CategoryUIDNetworkActivity:
		return "Network Activity"
	case CategoryUIDDiscovery:
		return "Discovery"
	case CategoryUIDApplicationActivity:
		return "Application Activity"
	default:
		return "Unknown"
	}
}

// Class UIDs for System Activity (category_uid=1)
const (
	ClassUIDFileActivity         = 1001
	ClassUIDKernelExtension      = 1002
	ClassUIDKernelActivity       = 1003
	ClassUIDMemoryActivity       = 1004
	ClassUIDModuleActivity       = 1005
	ClassUIDScheduledJobActivity = 1006
	ClassUIDProcessActivity      = 1007
)

// Class UIDs for Findings (category_uid=2)
const (
	ClassUIDSecurityFinding      = 2001
	ClassUIDVulnerabilityFinding = 2002
	ClassUIDComplianceFinding    = 2003
	ClassUIDDetectionFinding     = 2004
	ClassUIDIncidentFinding      = 2005
)

// Class UIDs for IAM (category_uid=3)
const (
	ClassUIDAccountChange        = 3001
	ClassUIDAuthentication       = 3002
	ClassUIDAuthorizeSession     = 3003
	ClassUIDEntityManagement     = 3004
	ClassUIDUserAccessManagement = 3005
	ClassUIDGroupManagement      = 3006
)

// Class UIDs for Network Activity (category_uid=4)
const (
	ClassUIDNetworkActivity     = 4001
	ClassUIDHTTPActivity        = 4002
	ClassUIDDNSActivity         = 4003
	ClassUIDDHCPActivity        = 4004
	ClassUIDRDPActivity         = 4005
	ClassUIDSMBActivity         = 4006
	ClassUIDSSHActivity         = 4007
	ClassUIDFTPActivity         = 4008
	ClassUIDEmailActivity       = 4009
	ClassUIDNetworkFileActivity = 4010
	ClassUIDEmailFileActivity   = 4011
	ClassUIDEmailURLActivity    = 4012
	ClassUIDNTPActivity         = 4013
	ClassUIDTunnelActivity      = 4014
)

// Class UIDs for Discovery (category_uid=5)
const (
	ClassUIDDeviceInventory    = 5001
	ClassUIDDeviceConfigState  = 5002
	ClassUIDUserInventory      = 5003
	ClassUIDOperatingSystem    = 5004
	ClassUIDServiceInfo        = 5005
	ClassUIDKernelObjectQuery  = 5006
	ClassUIDFileSystemActivity = 5007
)

// Class UIDs for Application Activity (category_uid=6)
const (
	ClassUIDWebResourceAccess    = 6001
	ClassUIDWebResourcesActivity = 6002
	ClassUIDAPIActivity          = 6003
	ClassUIDAuditActivity        = 6004
)

// ClassName returns the human-readable name for a class UID.
func ClassName(uid int) string {
	names := map[int]string{
		// System Activity
		ClassUIDFileActivity:         "File Activity",
		ClassUIDKernelExtension:      "Kernel Extension",
		ClassUIDKernelActivity:       "Kernel Activity",
		ClassUIDMemoryActivity:       "Memory Activity",
		ClassUIDModuleActivity:       "Module Activity",
		ClassUIDScheduledJobActivity: "Scheduled Job Activity",
		ClassUIDProcessActivity:      "Process Activity",
		// Findings
		ClassUIDSecurityFinding:      "Security Finding",
		ClassUIDVulnerabilityFinding: "Vulnerability Finding",
		ClassUIDComplianceFinding:    "Compliance Finding",
		ClassUIDDetectionFinding:     "Detection Finding",
		ClassUIDIncidentFinding:      "Incident Finding",
		// IAM
		ClassUIDAccountChange:        "Account Change",
		ClassUIDAuthentication:       "Authentication",
		ClassUIDAuthorizeSession:     "Authorize Session",
		ClassUIDEntityManagement:     "Entity Management",
		ClassUIDUserAccessManagement: "User Access Management",
		ClassUIDGroupManagement:      "Group Management",
		// Network Activity
		ClassUIDNetworkActivity:     "Network Activity",
		ClassUIDHTTPActivity:        "HTTP Activity",
		ClassUIDDNSActivity:         "DNS Activity",
		ClassUIDDHCPActivity:        "DHCP Activity",
		ClassUIDRDPActivity:         "RDP Activity",
		ClassUIDSMBActivity:         "SMB Activity",
		ClassUIDSSHActivity:         "SSH Activity",
		ClassUIDFTPActivity:         "FTP Activity",
		ClassUIDEmailActivity:       "Email Activity",
		ClassUIDNetworkFileActivity: "Network File Activity",
		ClassUIDEmailFileActivity:   "Email File Activity",
		ClassUIDEmailURLActivity:    "Email URL Activity",
		ClassUIDNTPActivity:         "NTP Activity",
		ClassUIDTunnelActivity:      "Tunnel Activity",
		// Discovery
		ClassUIDDeviceInventory:    "Device Inventory Info",
		ClassUIDDeviceConfigState:  "Device Config State",
		ClassUIDUserInventory:      "User Inventory Info",
		ClassUIDOperatingSystem:    "Operating System",
		ClassUIDServiceInfo:        "Service Info",
		ClassUIDKernelObjectQuery:  "Kernel Object Query",
		ClassUIDFileSystemActivity: "File System Activity",
		// Application Activity
		ClassUIDWebResourceAccess:    "Web Resource Access Activity",
		ClassUIDWebResourcesActivity: "Web Resources Activity",
		ClassUIDAPIActivity:          "API Activity",
		ClassUIDAuditActivity:        "Audit Activity",
	}
	if name, ok := names[uid]; ok {
		return name
	}
	return "Unknown"
}

// Severity IDs as defined by OCSF
const (
	SeverityIDUnknown       = 0
	SeverityIDInformational = 1
	SeverityIDLow           = 2
	SeverityIDMedium        = 3
	SeverityIDHigh          = 4
	SeverityIDCritical      = 5
	SeverityIDFatal         = 6
	SeverityIDOther         = 99
)

// SeverityName returns the human-readable name for a severity ID.
func SeverityName(id int) string {
	switch id {
	case SeverityIDUnknown:
		return "Unknown"
	case SeverityIDInformational:
		return "Informational"
	case SeverityIDLow:
		return "Low"
	case SeverityIDMedium:
		return "Medium"
	case SeverityIDHigh:
		return "High"
	case SeverityIDCritical:
		return "Critical"
	case SeverityIDFatal:
		return "Fatal"
	case SeverityIDOther:
		return "Other"
	default:
		return "Unknown"
	}
}

// Status IDs as defined by OCSF
const (
	StatusIDUnknown = 0
	StatusIDSuccess = 1
	StatusIDFailure = 2
	StatusIDOther   = 99
)

// StatusName returns the human-readable name for a status ID.
func StatusName(id int) string {
	switch id {
	case StatusIDUnknown:
		return "Unknown"
	case StatusIDSuccess:
		return "Success"
	case StatusIDFailure:
		return "Failure"
	case StatusIDOther:
		return "Other"
	default:
		return "Unknown"
	}
}

// Activity IDs common across event classes
const (
	ActivityIDUnknown = 0
	ActivityIDOther   = 99
)

// CalculateTypeUID computes the type_uid from class_uid and activity_id.
// OCSF formula: type_uid = class_uid * 100 + activity_id
func CalculateTypeUID(classUID, activityID int) int {
	return classUID*100 + activityID
}

// ParseTypeUID extracts class_uid and activity_id from type_uid.
func ParseTypeUID(typeUID int) (classUID, activityID int) {
	classUID = typeUID / 100
	activityID = typeUID % 100
	return
}
