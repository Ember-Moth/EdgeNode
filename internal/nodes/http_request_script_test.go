// Copyright 2026 GoEdge goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !script

package nodes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
)

func testNewScriptRequest(t *testing.T, rawURL string, group *serverconfigs.ScriptGroupConfig) (*HTTPRequest, *httptest.ResponseRecorder) {
	var rawReq = httptest.NewRequest(http.MethodGet, rawURL, nil)
	rawReq.RemoteAddr = "203.0.113.50:12345"

	var recorder = httptest.NewRecorder()

	var scriptsConfig = &serverconfigs.HTTPRequestScriptsConfig{
		RequestGroup: group,
	}
	if err := scriptsConfig.Init(); err != nil {
		t.Fatal(err)
	}

	var req = &HTTPRequest{
		RawReq:     rawReq,
		RawWriter:  recorder,
		ReqServer:  &serverconfigs.ServerConfig{Id: 1},
		ReqHost:    "scripttest.example.com",
		IsHTTPS:    true,
		uri:        "/hello?name=edge",
		varMapping: map[string]string{},
		web: &serverconfigs.HTTPWebConfig{
			IsOn:           true,
			RequestScripts: scriptsConfig,
		},
	}
	req.writer = NewHTTPWriter(req, recorder)
	return req, recorder
}

func testScriptGroup(code string) *serverconfigs.ScriptGroupConfig {
	return &serverconfigs.ScriptGroupConfig{
		IsOn: true,
		Scripts: []*serverconfigs.ScriptConfig{
			{IsOn: true, Code: code},
		},
	}
}

func TestScript_SetVariable(t *testing.T) {
	var group = testScriptGroup(`request.setVariable("greeting", "hi " + request.getArg("name"))`)
	req, _ := testNewScriptRequest(t, "https://scripttest.example.com/hello?name=edge", group)

	req.onRequest()

	if req.varMapping["greeting"] != "hi edge" {
		t.Fatal("unexpected variable:", req.varMapping["greeting"])
	}
}

func TestScript_ReadRequestInfo(t *testing.T) {
	var group = testScriptGroup(`
		request.setVariable("m", request.method());
		request.setVariable("s", request.scheme());
		request.setVariable("h", request.host());
		request.setVariable("p", request.path());
	`)
	req, _ := testNewScriptRequest(t, "https://scripttest.example.com/hello?name=edge", group)

	req.onRequest()

	if req.varMapping["m"] != "GET" {
		t.Fatal("method:", req.varMapping["m"])
	}
	if req.varMapping["s"] != "https" {
		t.Fatal("scheme:", req.varMapping["s"])
	}
	if req.varMapping["h"] != "scripttest.example.com" {
		t.Fatal("host:", req.varMapping["h"])
	}
	if req.varMapping["p"] != "/hello" {
		t.Fatal("path:", req.varMapping["p"])
	}
}

func TestScript_SetRequestHeader(t *testing.T) {
	var group = testScriptGroup(`request.setHeader("X-Edge-Script", "1"); request.deleteHeader("X-Remove-Me")`)
	req, _ := testNewScriptRequest(t, "https://scripttest.example.com/", group)
	req.RawReq.Header.Set("X-Remove-Me", "old")

	req.onRequest()

	if req.RawReq.Header.Get("X-Edge-Script") != "1" {
		t.Fatal("request header not set")
	}
	if req.RawReq.Header.Get("X-Remove-Me") != "" {
		t.Fatal("request header not deleted")
	}
}

func TestScript_SendResponse(t *testing.T) {
	var group = testScriptGroup(`
		if (request.getArg("blocked") === "1") {
			request.send(403, "denied by script");
		}
	`)
	req, recorder := testNewScriptRequest(t, "https://scripttest.example.com/?blocked=1", group)

	req.onRequest()

	if !req.writer.isFinished {
		t.Fatal("writer should be finished after send()")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatal("expected 403, got:", recorder.Code)
	}
	if recorder.Body.String() != "denied by script" {
		t.Fatal("unexpected body:", recorder.Body.String())
	}
}

func TestScript_Redirect(t *testing.T) {
	var group = testScriptGroup(`request.redirect(302, "https://example.com/new")`)
	req, recorder := testNewScriptRequest(t, "https://scripttest.example.com/old", group)

	req.onRequest()

	if !req.writer.isFinished {
		t.Fatal("writer should be finished after redirect()")
	}
	if recorder.Code != http.StatusFound {
		t.Fatal("expected 302, got:", recorder.Code)
	}
	if recorder.Header().Get("Location") != "https://example.com/new" {
		t.Fatal("unexpected Location:", recorder.Header().Get("Location"))
	}
}

func TestScript_NoScriptsFastPath(t *testing.T) {
	// web.RequestScripts为nil时应快速返回，不panic
	var req = &HTTPRequest{
		RawReq:    httptest.NewRequest(http.MethodGet, "https://x/", nil),
		ReqServer: &serverconfigs.ServerConfig{Id: 1},
		web:       &serverconfigs.HTTPWebConfig{IsOn: true},
	}
	req.onInit()
	req.onRequest()
}

func TestScript_DisabledGroup(t *testing.T) {
	var group = testScriptGroup(`request.setVariable("x", "1")`)
	group.IsOn = false // 关闭

	req, _ := testNewScriptRequest(t, "https://scripttest.example.com/", group)
	req.onRequest()

	if req.varMapping["x"] != "" {
		t.Fatal("disabled group should not run")
	}
}
