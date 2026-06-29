package ocsf

// EventMetadata contains metadata about the event.
type EventMetadata struct {
	// Version information
	Version        string `json:"version,omitempty"`         // OCSF schema version
	SchemaVersion  string `json:"schema_version,omitempty"`  // deprecated
	ProductVersion string `json:"product_version,omitempty"` // reporting product version

	// Product information
	Product *Product `json:"product,omitempty"`

	// Event identifiers
	UID            string   `json:"uid,omitempty"`             // unique event ID
	CorrelationUID string   `json:"correlation_uid,omitempty"` // correlation ID
	Sequence       int      `json:"sequence,omitempty"`        // sequence number
	Labels         []string `json:"labels,omitempty"`          // classification labels

	// Processing information
	LoggedTime    int64  `json:"logged_time,omitempty"`    // when event was logged
	ModifiedTime  int64  `json:"modified_time,omitempty"`  // when event was modified
	ProcessedTime int64  `json:"processed_time,omitempty"` // when event was processed
	OriginalTime  string `json:"original_time,omitempty"`  // original timestamp string

	// Source information
	LogName     string `json:"log_name,omitempty"`     // source log name
	LogVersion  string `json:"log_version,omitempty"`  // source log version
	LogProvider string `json:"log_provider,omitempty"` // log provider

	// Extension profiles
	Profiles []string `json:"profiles,omitempty"` // applied OCSF profiles

	// Custom extensions
	Extensions []Extension `json:"extensions,omitempty"`
}

// Product represents the product that generated the event.
type Product struct {
	Name       string   `json:"name,omitempty"`
	VendorName string   `json:"vendor_name,omitempty"`
	Version    string   `json:"version,omitempty"`
	UID        string   `json:"uid,omitempty"`
	URLString  string   `json:"url_string,omitempty"`
	Feature    *Feature `json:"feature,omitempty"`
	Lang       string   `json:"lang,omitempty"`
	CPEName    string   `json:"cpe_name,omitempty"`
}

// Feature represents a specific feature within a product.
type Feature struct {
	Name    string `json:"name,omitempty"`
	UID     string `json:"uid,omitempty"`
	Version string `json:"version,omitempty"`
}

// Extension represents an OCSF schema extension.
type Extension struct {
	Name    string `json:"name,omitempty"`
	UID     string `json:"uid,omitempty"`
	Version string `json:"version,omitempty"`
}

// Cloud contains cloud-related metadata.
type Cloud struct {
	Provider string        `json:"provider,omitempty"`
	Region   string        `json:"region,omitempty"`
	Zone     string        `json:"zone,omitempty"`
	Account  *Account      `json:"account,omitempty"`
	Org      *Organization `json:"org,omitempty"`
	Project  *ResourceUID  `json:"project,omitempty"`
}

// Account represents a cloud account.
type Account struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
	Type string `json:"type,omitempty"`
}

// Organization represents a cloud organization.
type Organization struct {
	Name   string `json:"name,omitempty"`
	UID    string `json:"uid,omitempty"`
	OUName string `json:"ou_name,omitempty"`
	OUID   string `json:"ou_uid,omitempty"`
}

// ResourceUID represents a generic resource identifier.
type ResourceUID struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
	Type string `json:"type,omitempty"`
}

// Actor represents the entity that performed the activity.
type Actor struct {
	User           *User           `json:"user,omitempty"`
	Process        *Process        `json:"process,omitempty"`
	Session        *Session        `json:"session,omitempty"`
	IDPInfo        *IDPInfo        `json:"idp,omitempty"`
	Invoked        *API            `json:"invoked,omitempty"`
	Authorizations []Authorization `json:"authorizations,omitempty"`
}

// User represents a user entity.
type User struct {
	Name       string        `json:"name,omitempty"`
	UID        string        `json:"uid,omitempty"`
	UIDAlt     string        `json:"uid_alt,omitempty"`
	Type       string        `json:"type,omitempty"`
	TypeID     int           `json:"type_id,omitempty"`
	Account    *Account      `json:"account,omitempty"`
	Credential *Credential   `json:"credential_uid,omitempty"`
	Domain     string        `json:"domain,omitempty"`
	EmailAddr  string        `json:"email_addr,omitempty"`
	Groups     []Group       `json:"groups,omitempty"`
	Org        *Organization `json:"org,omitempty"`
}

// Group represents a user group.
type Group struct {
	Name   string `json:"name,omitempty"`
	UID    string `json:"uid,omitempty"`
	Type   string `json:"type,omitempty"`
	Desc   string `json:"desc,omitempty"`
	Domain string `json:"domain,omitempty"`
}

// Credential represents authentication credentials.
type Credential struct {
	UID  string `json:"uid,omitempty"`
	Type string `json:"type,omitempty"`
}

// Process represents an operating system process.
type Process struct {
	Name          string   `json:"name,omitempty"`
	UID           string   `json:"uid,omitempty"`
	PID           int      `json:"pid,omitempty"`
	File          *File    `json:"file,omitempty"`
	User          *User    `json:"user,omitempty"`
	CmdLine       string   `json:"cmd_line,omitempty"`
	CreatedTime   int64    `json:"created_time,omitempty"`
	ParentProcess *Process `json:"parent_process,omitempty"`
	Integrity     string   `json:"integrity,omitempty"`
	IntegrityID   int      `json:"integrity_id,omitempty"`
}

// File represents a file object.
type File struct {
	Name         string `json:"name,omitempty"`
	Path         string `json:"path,omitempty"`
	UID          string `json:"uid,omitempty"`
	Type         string `json:"type,omitempty"`
	TypeID       int    `json:"type_id,omitempty"`
	Size         int64  `json:"size,omitempty"`
	Hashes       []Hash `json:"hashes,omitempty"`
	Owner        *User  `json:"owner,omitempty"`
	CreatedTime  int64  `json:"created_time,omitempty"`
	ModifiedTime int64  `json:"modified_time,omitempty"`
	AccessedTime int64  `json:"accessed_time,omitempty"`
}

// Hash represents a cryptographic hash.
type Hash struct {
	Algorithm   string `json:"algorithm,omitempty"`
	AlgorithmID int    `json:"algorithm_id,omitempty"`
	Value       string `json:"value,omitempty"`
}

// Session represents a user session.
type Session struct {
	UID            string `json:"uid,omitempty"`
	UUID           string `json:"uuid,omitempty"`
	CreatedTime    int64  `json:"created_time,omitempty"`
	ExpirationTime int64  `json:"expiration_time,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	IsMFA          bool   `json:"is_mfa,omitempty"`
	IsRemote       bool   `json:"is_remote,omitempty"`
	CredentialUID  string `json:"credential_uid,omitempty"`
	Terminal       string `json:"terminal,omitempty"`
	Count          int    `json:"count,omitempty"`
}

// IDPInfo represents identity provider information.
type IDPInfo struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

// API represents an API call.
type API struct {
	Name      string       `json:"name,omitempty"`
	UID       string       `json:"uid,omitempty"`
	Operation string       `json:"operation,omitempty"`
	Version   string       `json:"version,omitempty"`
	Service   *Service     `json:"service,omitempty"`
	Request   *APIRequest  `json:"request,omitempty"`
	Response  *APIResponse `json:"response,omitempty"`
}

// Service represents a service.
type Service struct {
	Name    string   `json:"name,omitempty"`
	UID     string   `json:"uid,omitempty"`
	Version string   `json:"version,omitempty"`
	Labels  []string `json:"labels,omitempty"`
}

// APIRequest represents an API request.
type APIRequest struct {
	UID        string         `json:"uid,omitempty"`
	Containers []any          `json:"containers,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
	Flags      []string       `json:"flags,omitempty"`
}

// APIResponse represents an API response.
type APIResponse struct {
	Code         int            `json:"code,omitempty"`
	Message      string         `json:"message,omitempty"`
	Error        string         `json:"error,omitempty"`
	ErrorMessage string         `json:"error_message,omitempty"`
	Data         map[string]any `json:"data,omitempty"`
	Flags        []string       `json:"flags,omitempty"`
}

// Authorization represents an authorization grant.
type Authorization struct {
	Decision   string  `json:"decision,omitempty"`
	DecisionID int     `json:"decision_id,omitempty"`
	Policy     *Policy `json:"policy,omitempty"`
}

// Policy represents a security policy.
type Policy struct {
	Name    string `json:"name,omitempty"`
	UID     string `json:"uid,omitempty"`
	Version string `json:"version,omitempty"`
	Desc    string `json:"desc,omitempty"`
	Group   *Group `json:"group,omitempty"`
}
