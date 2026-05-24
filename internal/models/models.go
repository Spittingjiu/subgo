package models

import "time"

type AdminSettings struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Source struct {
	ID             int64      `json:"id"`
	Name           string     `json:"name"`
	Type           string     `json:"source_type"`
	PanelURL       string     `json:"panel_url"`
	Enabled        bool       `json:"enabled"`
	LastSyncAt     *time.Time `json:"last_sync_at,omitempty"`
	LastSyncStatus string     `json:"last_sync_status"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type Node struct {
	ID                 int64     `json:"id"`
	SourceID           int64     `json:"source_id"`
	SourceName         string    `json:"source_name,omitempty"`
	SourceType         string    `json:"source_type,omitempty"`
	DisplayNo          string    `json:"display_no"`
	NodeHash           string    `json:"node_hash"`
	RawLink            string    `json:"raw_link"`
	NodeName           string    `json:"node_name"`
	Protocol           string    `json:"protocol"`
	Enabled            bool      `json:"enabled"`
	ConnectivityStatus *string   `json:"connectivity_status,omitempty"`
	ConnectivityLatMs  *int64    `json:"connectivity_latency_ms,omitempty"`
	ConnectivityError  *string   `json:"connectivity_last_error,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type Subscription struct {
	ID                   int64      `json:"id"`
	Name                 string     `json:"name"`
	Token                string     `json:"token"`
	SourceIDsJSON        string     `json:"-"`
	NodeHashesJSON       string     `json:"-"`
	SourceIDs            []int64    `json:"source_ids"`
	NodeHashes           []string   `json:"node_hashes"`
	SourceNames          []string   `json:"source_names,omitempty"`
	Enabled              bool       `json:"enabled"`
	AutoPruneUnreachable bool       `json:"auto_prune_unreachable"`
	AccessCount          int64      `json:"access_count"`
	LastAccessedAt       *time.Time `json:"last_accessed_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	PlainURL             string     `json:"plain_url,omitempty"`
}

type SubscriptionLog struct {
	ID               int64     `json:"id"`
	Token            string    `json:"token"`
	SubscriptionID   int64     `json:"subscription_id"`
	SubscriptionName string    `json:"subscription_name"`
	RouteType        string    `json:"route_type"`
	ClientIP         string    `json:"client_ip"`
	UserAgent        string    `json:"user_agent"`
	CreatedAt        time.Time `json:"created_at"`
}
