package auth

// UserInfo carries display fields extracted from the upstream auth response.
// The upstream returns these under the "user" key in the login JSON response.
type UserInfo struct {
	UID       string `json:"uid"`       // "uid":       "carlososiel"
	CN        string `json:"cn"`        // "cn":        "Carlos Rojas"
	Mail      string `json:"mail"`      // "mail":      "crojas@grainchain.io"
	GivenName string `json:"givenName"` // "givenName": "Carlos"
	SN        string `json:"sn"`        // "sn":        "Rojas"
}
