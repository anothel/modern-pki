package observability

import (
	"expvar"
	"strconv"
	"time"
)

var (
	httpRequestMetrics = expvar.NewMap("modern_pki_http_requests_total")
	httpEventMetrics   = expvar.NewMap("modern_pki_http_events_total")
	operationMetrics   = expvar.NewMap("modern_pki_operations_total")
	operationLatencyMS = expvar.NewMap("modern_pki_operation_latency_ms_total")
)

func RecordHTTPRequest(boundary string, status int) {
	if boundary == "" {
		boundary = "unknown"
	}
	httpRequestMetrics.Add(boundary+":"+strconv.Itoa(status), 1)
}

func RecordEvent(key string) {
	httpEventMetrics.Add(key, 1)
}

func ObserveOperation(boundary string, operation string, start time.Time, err error) {
	status := "success"
	if err != nil {
		status = "error"
	}
	key := boundary + ":" + operation + ":" + status
	operationMetrics.Add(key, 1)
	operationLatencyMS.Add(key, time.Since(start).Milliseconds())
}

func HTTPRequestMetricValue(key string) int64 {
	return expvarIntValue(httpRequestMetrics.Get(key))
}

func EventMetricValue(key string) int64 {
	return expvarIntValue(httpEventMetrics.Get(key))
}

func OperationMetricValue(key string) int64 {
	return expvarIntValue(operationMetrics.Get(key))
}

func expvarIntValue(value expvar.Var) int64 {
	if value == nil {
		return 0
	}
	parsed, _ := strconv.ParseInt(value.String(), 10, 64)
	return parsed
}
