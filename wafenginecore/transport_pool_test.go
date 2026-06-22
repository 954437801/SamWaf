package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafproxy"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestTransportPoolCleanupOnBackendError 测试后端下线后重新上线时Transport池清理机制
func TestTransportPoolCleanupOnBackendError(t *testing.T) {
	// 初始化日志
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "console")

	// 创建后端服务器
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Backend OK"))
	})
	backend := httptest.NewServer(backendHandler)
	defer backend.Close()

	// 解析后端URL
	targetURL, _ := url.Parse(backend.URL)

	// 创建WAF引擎（使用路由快照RCU）
	waf := &WafEngine{
		TransportPool: make(map[string]*http.Transport),
	}
	waf.InitRouting()

	// 模拟主机配置
	hostCode := "test-host-code"
	hostName := "test.example.com"

	// 提取后端IP和端口
	backendAddr := backend.Listener.Addr().String()
	host, port, _ := net.SplitHostPort(backendAddr)
	portInt := 80
	fmt.Sscanf(port, "%d", &portInt)

	// 通过路由快照设置主机信息（copy-on-write）
	nt := waf.rt().clone()
	nt.HostCode[hostCode] = hostName
	nt.HostTarget[hostName] = &wafenginmodel.HostSafe{
		Host: model.Hosts{
			Code:        hostCode,
			Remote_ip:   host,
			Remote_port: portInt,
			Port:        portInt,
		},
	}
	waf.routing.Store(nt)

	// 创建反向代理
	rp := wafproxy.NewSingleHostReverseProxyCustomHeader(targetURL, map[string]string{}, map[string]string{})
	transport, _ := waf.createTransport(&http.Request{}, hostName, 0, model.LoadBalance{}, waf.rt().HostTarget[hostName])

	// 将Transport存入池中，模拟getOrCreateTransport的效果
	transportKey := waf.generateTransportKey(hostName, 0, model.LoadBalance{}, waf.rt().HostTarget[hostName])
	waf.TransportPool[transportKey] = transport

	rp.Transport = transport
	rp.ErrorHandler = waf.errorResponse()

	// 测试1: 正常请求 - 应该成功
	t.Log("测试1: 后端正常运行时的请求")
	req1 := httptest.NewRequest("GET", "http://"+hostName+"/", nil)
	ctx1 := context.WithValue(req1.Context(), "waf_context", innerbean.WafHttpContextData{
		Weblog:   &innerbean.WebLog{URL: "/", METHOD: "GET"},
		HostCode: hostCode,
	})
	req1 = req1.WithContext(ctx1)

	rec1 := httptest.NewRecorder()
	rp.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Errorf("期望状态码200，实际得到 %d", rec1.Code)
	}
	t.Logf("第一次请求成功，状态码: %d", rec1.Code)

	// 检查Transport是否在池中
	if _, exists := waf.TransportPool[transportKey]; !exists {
		t.Error("Transport应该已经被存入池中")
	} else {
		t.Log("✓ Transport已在池中")
	}

	// 测试2: 关闭后端服务器
	t.Log("\n测试2: 关闭后端服务器")
	backend.Close()

	// 等待一下确保连接失效
	time.Sleep(100 * time.Millisecond)

	// 测试3: 向后端发送请求 - 应该失败并触发Transport清理
	t.Log("测试3: 后端下线后的请求（应该返回502/503）")
	req2 := httptest.NewRequest("GET", "http://"+hostName+"/", nil)
	ctx2 := context.WithValue(req2.Context(), "waf_context", innerbean.WafHttpContextData{
		Weblog:   &innerbean.WebLog{URL: "/", METHOD: "GET"},
		HostCode: hostCode,
	})
	req2 = req2.WithContext(ctx2)

	rec2 := httptest.NewRecorder()
	rp.ServeHTTP(rec2, req2)

	if rec2.Code == http.StatusOK {
		t.Error("后端已关闭，请求应该失败")
	}
	// 连接拒绝类错误应返回503（防火墙不暴露后端详情）
	if rec2.Code == http.StatusServiceUnavailable || rec2.Code == http.StatusBadGateway {
		t.Logf("✓ 请求返回 %d，状态码正确", rec2.Code)
	} else {
		t.Logf("注意: 状态码为 %d (预期503/502)", rec2.Code)
	}

	// 检查Transport是否被清理
	if _, exists := waf.TransportPool[transportKey]; exists {
		t.Error("Transport应该在错误后被清理")
	} else {
		t.Log("✓ Transport已被正确清理")
	}

	// 测试4: 重新启动后端服务器
	t.Log("\n测试4: 重新启动后端服务器")
	backend2 := httptest.NewServer(backendHandler)
	defer backend2.Close()

	// 更新路由快照中的后端地址
	backendAddr2 := backend2.Listener.Addr().String()
	host2, port2, _ := net.SplitHostPort(backendAddr2)
	portInt2 := 80
	fmt.Sscanf(port2, "%d", &portInt2)

	nt2 := waf.rt().clone()
	nt2.HostTarget[hostName] = &wafenginmodel.HostSafe{
		Host: model.Hosts{
			Code:        hostCode,
			Remote_ip:   host2,
			Remote_port: portInt2,
			Port:        portInt2,
		},
	}
	waf.routing.Store(nt2)

	// 使用getOrCreateTransport获取新Transport（池已被清空，应该创建新的）
	targetURL2, _ := url.Parse(backend2.URL)
	newTransport := waf.getOrCreateTransport(&http.Request{}, hostName, 0, model.LoadBalance{}, waf.rt().HostTarget[hostName])

	rp2 := wafproxy.NewSingleHostReverseProxyCustomHeader(targetURL2, map[string]string{}, map[string]string{})
	rp2.Transport = newTransport
	rp2.ErrorHandler = waf.errorResponse()

	// 等待一下让新服务器就绪
	time.Sleep(100 * time.Millisecond)

	// 测试5: 后端重新上线后的请求（使用新Transport，应该成功）
	t.Log("测试5: 后端重新上线后的请求（使用新Transport，应该成功）")
	req3 := httptest.NewRequest("GET", "http://"+hostName+"/", nil)
	ctx3 := context.WithValue(req3.Context(), "waf_context", innerbean.WafHttpContextData{
		Weblog:   &innerbean.WebLog{URL: "/", METHOD: "GET"},
		HostCode: hostCode,
	})
	req3 = req3.WithContext(ctx3)

	rec3 := httptest.NewRecorder()
	rp2.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Errorf("后端重新上线后，请求应该成功，实际状态码: %d", rec3.Code)
	} else {
		t.Logf("✓ 第三次请求成功，状态码: %d", rec3.Code)
	}

	// 验证响应内容
	body, _ := io.ReadAll(rec3.Body)
	if string(body) != "Backend OK" {
		t.Errorf("响应内容不正确: %s", string(body))
	}

	// 验证新Transport已被重新缓存到池中
	newTransportKey := waf.generateTransportKey(hostName, 0, model.LoadBalance{}, waf.rt().HostTarget[hostName])
	if _, exists := waf.TransportPool[newTransportKey]; !exists {
		t.Error("新创建的Transport应该被缓存到池中")
	} else {
		t.Log("✓ 新Transport已正确缓存到池中")
	}

	t.Log("\n✓ Transport池清理后重建机制工作正常")
}

// TestTransportIdleConnTimeout 测试空闲连接超时配置（默认值+自定义值）
func TestTransportIdleConnTimeout(t *testing.T) {
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "console")

	waf := &WafEngine{}
	hostTarget := &wafenginmodel.HostSafe{
		Host: model.Hosts{
			ResponseTimeOut: 30,
		},
	}

	// 测试1: 默认配置（未设置TransportJSON）
	t.Log("测试1: 未配置TransportJSON时的默认IdleConnTimeout（Go零值，无超时）")
	transport, _ := waf.createTransport(&http.Request{}, "test", 0, model.LoadBalance{}, hostTarget)

	if transport.IdleConnTimeout != 0 {
		t.Errorf("未配置时应为0（无超时），实际为 %v", transport.IdleConnTimeout)
	} else {
		t.Logf("✓ 未配置时IdleConnTimeout为0（无超时，依赖Transport清理兜底）")
	}

	// 测试2: 自定义配置
	t.Log("测试2: 自定义IdleConnTimeout配置")
	hostTarget2 := &wafenginmodel.HostSafe{
		Host: model.Hosts{
			ResponseTimeOut: 30,
			TransportJSON:   `{"idle_conn_timeout": 60}`,
		},
	}
	transport2, _ := waf.createTransport(&http.Request{}, "test", 0, model.LoadBalance{}, hostTarget2)

	if transport2.IdleConnTimeout != 60*time.Second {
		t.Errorf("自定义IdleConnTimeout应该是60秒，实际是 %v", transport2.IdleConnTimeout)
	} else {
		t.Logf("✓ 自定义IdleConnTimeout正确设置为: %v", transport2.IdleConnTimeout)
	}
}

// TestGenerateTransportKey 测试Transport键生成
func TestGenerateTransportKey(t *testing.T) {
	waf := &WafEngine{}

	hostTarget := &wafenginmodel.HostSafe{
		Host: model.Hosts{
			Remote_ip:          "10.0.0.1",
			Remote_port:        8080,
			InsecureSkipVerify: 0,
		},
	}

	// 测试非负载均衡key
	t.Run("非负载均衡", func(t *testing.T) {
		keyNormal := waf.generateTransportKey("example.com", 0, model.LoadBalance{}, hostTarget)
		expectedNormal := "example.com_0_10.0.0.1_8080_0"
		if keyNormal != expectedNormal {
			t.Errorf("key: 期望 %s, 实际 %s", expectedNormal, keyNormal)
		} else {
			t.Logf("✓ 非负载均衡key正确: %s", keyNormal)
		}
	})

	// 测试负载均衡key
	t.Run("负载均衡", func(t *testing.T) {
		lb := model.LoadBalance{
			Remote_ip:   "10.0.0.2",
			Remote_port: 8081,
		}
		keyLB := waf.generateTransportKey("example.com", 1, lb, hostTarget)
		expectedLB := "example.com_1_10.0.0.2_8081_0"
		if keyLB != expectedLB {
			t.Errorf("key: 期望 %s, 实际 %s", expectedLB, keyLB)
		} else {
			t.Logf("✓ 负载均衡key正确: %s", keyLB)
		}
	})

	// 测试InsecureSkipVerify不同值
	t.Run("InsecureSkipVerify变化", func(t *testing.T) {
		hostTarget2 := &wafenginmodel.HostSafe{
			Host: model.Hosts{
				Remote_ip:          "10.0.0.1",
				Remote_port:        8080,
				InsecureSkipVerify: 1,
			},
		}
		keyVerify := waf.generateTransportKey("example.com", 0, model.LoadBalance{}, hostTarget2)
		expectedVerify := "example.com_0_10.0.0.1_8080_1"
		if keyVerify != expectedVerify {
			t.Errorf("key: 期望 %s, 实际 %s", expectedVerify, keyVerify)
		} else {
			t.Logf("✓ InsecureSkipVerify不同时key正确: %s", keyVerify)
		}
	})
}
