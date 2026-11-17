package main

// Wire and domain types mirrored from the CumulusVPN shared core
// (clients/core-ts/src/types.ts). Field names on wire types are snake_case
// because they are parsed directly from the gateway control API.

const (
	controlPort = 51821
	wgPort      = 51820
	powBits     = 20
)

// Keypair is a WireGuard Curve25519 keypair, standard base64 with padding.
type Keypair struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

// ApiEnvelope is the discriminated success/error envelope every API returns.
type ApiEnvelope struct {
	Status string          `json:"status"`
	Data   []byte          `json:"-"`
	Raw    []byte          `json:"-"`
	Err    *ApiErrorDetail `json:"-"`
}

// ApiErrorDetail is the body of an error envelope.
type ApiErrorDetail struct {
	Code    string `json:"code"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

// Transport is one dialable transport a gateway advertises.
type Transport struct {
	Type   string            `json:"type"`
	Port   int               `json:"port"`
	Params map[string]string `json:"params,omitempty"`
}

// InfoResponse is GET /v1/info.
type InfoResponse struct {
	Country          string      `json:"country"`
	Region           string      `json:"region"`
	City             string      `json:"city"`
	Load             float64     `json:"load"`
	Capacity         int         `json:"capacity"`
	Version          string      `json:"version"`
	MinClientVersion string      `json:"min_client_version"`
	BuildCommit      string      `json:"build_commit"`
	PeersPersisted   *bool       `json:"peers_persisted"`
	ServerPubkey     string      `json:"server_pubkey"`
	SignPubkey       string      `json:"sign_pubkey"`
	Transports       []Transport `json:"transports"`
}

// EnrollResponse is POST /v1/enroll.
type EnrollResponse struct {
	ServerPubkey string `json:"server_pubkey"`
	Endpoint     string `json:"endpoint"`
	AssignedIP   string `json:"assigned_ip"`
	DNS          string `json:"dns"`
}

// GatewayInfo is a reachable, signature-verified gateway.
type GatewayInfo struct {
	InfoResponse
	IP         string `json:"ip"`
	ControlURL string `json:"controlUrl"`
}

// SeedGateway is a last-known gateway in the signed directory snapshot.
type SeedGateway struct {
	IP         string `json:"ip"`
	Country    string `json:"country"`
	SignPubkey string `json:"sign_pubkey"`
}

// Directory is the signed directory.json. PaymentAddress and PriceFlux are
// part of the signed document and must stay here so signature verification
// covers the exact bytes the fleet published; the CLI never reads them.
type Directory struct {
	Version        int           `json:"version"`
	Updated        string        `json:"updated"`
	PaymentAddress string        `json:"payment_address"`
	PriceFlux      float64       `json:"price_flux"`
	Specs          []string      `json:"specs"`
	SeedGateways   []SeedGateway `json:"seed_gateways"`
	SignPubkey     string        `json:"sign_pubkey"`
	Sig            string        `json:"sig"`
}
