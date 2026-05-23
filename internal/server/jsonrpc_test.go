package server

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestDecodeJSONRPC_ValidRequest(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}`)
	m, err := DecodeJSONRPC(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !m.IsRequest() {
		t.Fatalf("IsRequest = false, want true")
	}
	if m.Method != "ping" {
		t.Errorf("Method = %q, want ping", m.Method)
	}
	if string(m.ID) != "1" {
		t.Errorf("ID = %s, want 1", m.ID)
	}
}

func TestDecodeJSONRPC_StringID(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":"abc","method":"ping"}`)
	m, err := DecodeJSONRPC(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(m.ID) != `"abc"` {
		t.Fatalf("ID = %s, want \"abc\" (quoted)", m.ID)
	}
}

func TestDecodeJSONRPC_Notification(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	m, err := DecodeJSONRPC(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m.IsRequest() {
		t.Errorf("notification reported IsRequest=true")
	}
	if !m.IsNotification() {
		t.Errorf("IsNotification=false, want true")
	}
}

func TestDecodeJSONRPC_BadJSON(t *testing.T) {
	_, err := DecodeJSONRPC([]byte(`{not json`))
	if err == nil {
		t.Fatal("want error for malformed JSON")
	}
	if !errors.Is(err, ErrJSONRPCParse) {
		t.Fatalf("err = %v, want ErrJSONRPCParse", err)
	}
}

func TestDecodeJSONRPC_BadEnvelope(t *testing.T) {
	_, err := DecodeJSONRPC([]byte(`{"jsonrpc":"1.0","id":1,"method":"x"}`))
	if err == nil {
		t.Fatal("want error for wrong jsonrpc version")
	}
	if !errors.Is(err, ErrJSONRPCInvalidRequest) {
		t.Fatalf("err = %v, want ErrJSONRPCInvalidRequest", err)
	}
}

func TestNewResultResponse_RoundTrip(t *testing.T) {
	resp, err := NewResultResponse(json.RawMessage(`5`), map[string]string{"hello": "world"})
	if err != nil {
		t.Fatalf("NewResultResponse: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q", resp.JSONRPC)
	}
	if resp.Error != nil {
		t.Errorf("Error = %+v, want nil", resp.Error)
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Re-parse and confirm the result is preserved.
	var back JSONRPCMessage
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(back.Result) != `{"hello":"world"}` {
		t.Errorf("Result = %s", back.Result)
	}
}

func TestNewErrorResponse_NilIDBecomesNull(t *testing.T) {
	resp := NewErrorResponse(nil, ErrCodeParseError, "boom", nil)
	if string(resp.ID) != "null" {
		t.Errorf("ID = %q, want null literal", resp.ID)
	}
	if resp.Error == nil || resp.Error.Code != ErrCodeParseError {
		t.Errorf("Error = %+v", resp.Error)
	}
}
