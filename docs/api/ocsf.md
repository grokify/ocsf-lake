# OCSF Types

The ocsf package provides Go types for OCSF (Open Cybersecurity Schema Framework) events.

## Package

```go
import "github.com/grokify/ocsf-lake/pkg/ocsf"
```

## Category UIDs

Categories are high-level groupings of event classes.

| Constant | Value | Description |
|----------|-------|-------------|
| `CategoryUIDSystemActivity` | 1 | System activity events |
| `CategoryUIDFindingsActivity` | 2 | Security findings |
| `CategoryUIDIAMActivity` | 3 | Identity & Access Management |
| `CategoryUIDNetworkActivity` | 4 | Network activity events |
| `CategoryUIDDiscovery` | 5 | Discovery events |
| `CategoryUIDApplicationActivity` | 6 | Application activity events |

### CategoryName

```go
func CategoryName(uid int) string
```

Returns the human-readable name for a category UID.

## Class UIDs

### System Activity (Category 1)

| Constant | Value | Description |
|----------|-------|-------------|
| `ClassUIDFileActivity` | 1001 | File system operations |
| `ClassUIDKernelExtension` | 1002 | Kernel extension events |
| `ClassUIDKernelActivity` | 1003 | Kernel activity |
| `ClassUIDMemoryActivity` | 1004 | Memory operations |
| `ClassUIDModuleActivity` | 1005 | Module loading/unloading |
| `ClassUIDScheduledJobActivity` | 1006 | Scheduled tasks |
| `ClassUIDProcessActivity` | 1007 | Process creation/termination |

### Findings (Category 2)

| Constant | Value | Description |
|----------|-------|-------------|
| `ClassUIDSecurityFinding` | 2001 | Security findings |
| `ClassUIDVulnerabilityFinding` | 2002 | Vulnerability detections |
| `ClassUIDComplianceFinding` | 2003 | Compliance issues |
| `ClassUIDDetectionFinding` | 2004 | Detection results |
| `ClassUIDIncidentFinding` | 2005 | Incident findings |

### IAM (Category 3)

| Constant | Value | Description |
|----------|-------|-------------|
| `ClassUIDAccountChange` | 3001 | Account modifications |
| `ClassUIDAuthentication` | 3002 | Authentication events |
| `ClassUIDAuthorizeSession` | 3003 | Session authorization |
| `ClassUIDEntityManagement` | 3004 | Entity management |
| `ClassUIDUserAccessManagement` | 3005 | User access changes |
| `ClassUIDGroupManagement` | 3006 | Group management |

### Network Activity (Category 4)

| Constant | Value | Description |
|----------|-------|-------------|
| `ClassUIDNetworkActivity` | 4001 | General network activity |
| `ClassUIDHTTPActivity` | 4002 | HTTP traffic |
| `ClassUIDDNSActivity` | 4003 | DNS queries/responses |
| `ClassUIDDHCPActivity` | 4004 | DHCP operations |
| `ClassUIDRDPActivity` | 4005 | RDP connections |
| `ClassUIDSMBActivity` | 4006 | SMB operations |
| `ClassUIDSSHActivity` | 4007 | SSH connections |
| `ClassUIDFTPActivity` | 4008 | FTP transfers |
| `ClassUIDEmailActivity` | 4009 | Email operations |
| `ClassUIDNetworkFileActivity` | 4010 | Network file access |
| `ClassUIDEmailFileActivity` | 4011 | Email attachments |
| `ClassUIDEmailURLActivity` | 4012 | Email URLs |
| `ClassUIDNTPActivity` | 4013 | NTP operations |
| `ClassUIDTunnelActivity` | 4014 | Tunnel/VPN activity |

### Discovery (Category 5)

| Constant | Value | Description |
|----------|-------|-------------|
| `ClassUIDDeviceInventory` | 5001 | Device inventory |
| `ClassUIDDeviceConfigState` | 5002 | Device configuration |
| `ClassUIDUserInventory` | 5003 | User inventory |
| `ClassUIDOperatingSystem` | 5004 | OS information |
| `ClassUIDServiceInfo` | 5005 | Service information |
| `ClassUIDKernelObjectQuery` | 5006 | Kernel object queries |
| `ClassUIDFileSystemActivity` | 5007 | File system queries |

### Application Activity (Category 6)

| Constant | Value | Description |
|----------|-------|-------------|
| `ClassUIDWebResourceAccess` | 6001 | Web resource access |
| `ClassUIDWebResourcesActivity` | 6002 | Web resources activity |
| `ClassUIDAPIActivity` | 6003 | API calls |
| `ClassUIDAuditActivity` | 6004 | Audit events |

### ClassName

```go
func ClassName(uid int) string
```

Returns the human-readable name for a class UID.

## Severity IDs

| Constant | Value | Description |
|----------|-------|-------------|
| `SeverityIDUnknown` | 0 | Unknown severity |
| `SeverityIDInformational` | 1 | Informational |
| `SeverityIDLow` | 2 | Low severity |
| `SeverityIDMedium` | 3 | Medium severity |
| `SeverityIDHigh` | 4 | High severity |
| `SeverityIDCritical` | 5 | Critical severity |
| `SeverityIDFatal` | 6 | Fatal severity |
| `SeverityIDOther` | 99 | Other |

### SeverityName

```go
func SeverityName(id int) string
```

Returns the human-readable name for a severity ID.

## Status IDs

| Constant | Value | Description |
|----------|-------|-------------|
| `StatusIDUnknown` | 0 | Unknown status |
| `StatusIDSuccess` | 1 | Success |
| `StatusIDFailure` | 2 | Failure |
| `StatusIDOther` | 99 | Other |

### StatusName

```go
func StatusName(id int) string
```

Returns the human-readable name for a status ID.

## Type UID Calculation

OCSF type UIDs are calculated from class UID and activity ID:

```
type_uid = class_uid * 100 + activity_id
```

### CalculateTypeUID

```go
func CalculateTypeUID(classUID, activityID int) int
```

Computes the type_uid from class_uid and activity_id.

### ParseTypeUID

```go
func ParseTypeUID(typeUID int) (classUID, activityID int)
```

Extracts class_uid and activity_id from type_uid.

**Example:**

```go
// Authentication Login event
typeUID := ocsf.CalculateTypeUID(ocsf.ClassUIDAuthentication, 1)
// typeUID = 300201

classUID, activityID := ocsf.ParseTypeUID(300201)
// classUID = 3002, activityID = 1
```

## Event Types

### Event

The base OCSF event structure:

```go
type Event struct {
    ClassUID    int    `json:"class_uid"`
    ClassName   string `json:"class_name,omitempty"`
    CategoryUID int    `json:"category_uid"`
    ActivityID  int    `json:"activity_id"`
    TypeUID     int    `json:"type_uid"`
    TypeName    string `json:"type_name,omitempty"`
    SeverityID  int    `json:"severity_id,omitempty"`
    Severity    string `json:"severity,omitempty"`
    Time        int64  `json:"time"`
    // ... additional fields
}
```

### StoredEvent

Events as stored in the data lake:

```go
type StoredEvent struct {
    ID            string         `json:"id"`
    ClassUID      int            `json:"class_uid"`
    CategoryUID   int            `json:"category_uid"`
    ActivityID    int            `json:"activity_id"`
    TypeUID       int            `json:"type_uid"`
    SeverityID    int            `json:"severity_id,omitempty"`
    StatusID      int            `json:"status_id,omitempty"`
    Time          int64          `json:"time"`
    IngestedAt    time.Time      `json:"ingested_at"`
    Source        string         `json:"source"`
    SchemaVersion string         `json:"schema_version"`
    Payload       map[string]any `json:"payload"`
    RawData       string         `json:"raw_data,omitempty"`
}
```

## Parsing Functions

### ParseEvent

```go
func ParseEvent(data []byte) (*Event, error)
```

Parses a JSON payload into a base Event structure.

### ParsePayload

```go
func ParsePayload(data []byte) (map[string]any, error)
```

Parses a JSON payload into a generic map.
