package qlog

import (
	"context"

	"github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
)

const EventSchema = "urn:ietf:params:qlog:events:http3-12"

func DefaultConnectionTracer(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	return qlog.DefaultConnectionTracerWithSchemas(ctx, isClient, connID, []string{qlog.EventSchema, EventSchema})
}
