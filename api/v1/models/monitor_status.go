package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
)

// MonitorStatus Status of the node monitor
// swagger:model MonitorStatus
type MonitorStatus struct {

	// Number of CPUs to listen on for events.
	Cpus int64 `json:"cpus,omitempty"`

	// Number of samples lost by perf.
	Lost int64 `json:"lost,omitempty"`

	// Number of pages used for the perf ring buffer.
	Npages int64 `json:"npages,omitempty"`

	// Pages size used for the perf ring buffer.
	Pagesize int64 `json:"pagesize,omitempty"`

	// Number of unknown samples.
	Unknown int64 `json:"unknown,omitempty"`
}

// Validate validates this monitor status
func (m *MonitorStatus) Validate(formats strfmt.Registry) error {
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
