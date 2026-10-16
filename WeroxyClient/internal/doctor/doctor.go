// Package doctor performs bounded, read-only connectivity diagnostics.
package doctor

import (
	"context"

	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"weroxy/client/internal/config"
	"weroxy/client/internal/harden"
	wp "weroxy/client/internal/protocol/weroxy"
	"weroxy/client/internal/secure"
)

// Check never contains a credential, address, certificate contents or raw network error.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Report is safe to print or attach to a diagnostic bundle.
type Report struct {
	Checks    []Check        `json:"checks"`
	OK        bool           `json:"ok"`
	Hardening []harden.Check `json:"hardening"`
}

func Run(parent context.Context, cfg config.Config) Report {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	report := Report{OK: true, Hardening: harden.Inspect(ctx)}
	add := func(name, status, detail string) {
		report.Checks = append(report.Checks, Check{Name: name, Status: status, Detail: detail})
		if status == "fail" {
			report.OK = false
		}
	}
	host, _, err := net.SplitHostPort(cfg.Server)
	if err != nil {
		add("dns", "fail", "服务端地址无效")
		return report
	}
	if _, err := net.DefaultResolver.LookupHost(ctx, host); err != nil {
		add("dns", "fail", "服务端名称无法解析")
		return report
	}
	add("dns", "pass", "服务端名称可解析")
	dial := func(addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", addr)
	}
	conn, err := dial(cfg.Server)
	if err != nil {
		add("control_port", "fail", "控制端口连接失败；请检查 Host、Control Port、Docker 发布及防火墙")
		return report
	}
	defer conn.Close()
	add("control_port", "pass", "控制端口 TCP 连接成功")
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	token, err := config.ReadToken(strings.NewReader(cfg.Key))
	if err != nil {
		add("auth", "fail", "设备凭据格式无效")
		return report
	}
	defer func() {
		for i := range token {
			token[i] = 0
		}
	}()
	credential := secure.Derive(token, "control")
	encrypted, _, err := secure.Client(conn, 'C', credential.ID[:], credential.PSK, nil, nil)
	if err != nil {
		add("auth", "fail", "安全握手失败；请核对两端版本与 Key")
		return report
	}
	conn = encrypted
	reader := wp.Reader{R: conn}
	add("transport", "pass", "控制与握手已保护；业务流沿用原协议")
	if err := write(conn, wp.TypeDiagnose, 2, cfg.DeviceID); err != nil {
		add("auth", "fail", "诊断请求发送失败")
		return report
	}
	var frame wp.Frame
	frame, err = reader.Next()
	if err != nil {
		add("auth", "fail", "诊断响应读取失败")
		return report
	}
	if frame.Type == wp.TypeError {
		add("auth", "fail", "设备凭据被拒绝或已停用；请在 Server Web 核对 Key、设备状态及客户端版本")
		return report
	}
	if frame.Type != wp.TypeDiagnose {
		add("auth", "fail", "服务端不支持诊断协议")
		return report
	}
	parts, err := wp.Strings(frame.Body, 2)
	if err != nil {
		add("auth", "fail", "诊断响应格式无效")
		return report
	}
	add("auth", "pass", "设备凭据有效；未替换运行中的控制连接")
	serverTime, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		add("time", "fail", "服务端时间格式无效")
	} else {
		skew := time.Since(serverTime)
		if skew < 0 {
			skew = -skew
		}
		if skew > 2*time.Minute {
			add("time", "fail", "两端时间偏差超过两分钟")
		} else {
			add("time", "pass", "两端时间偏差在两分钟内")
		}
	}
	if parts[1] == "" {
		add("data_ports", "skip", "该设备目前没有正在服务的数据端口")
	} else {
		ports := strings.Split(parts[1], ",")
		if len(ports) > 200 {
			add("data_ports", "fail", "服务端返回过多数据端口")
		} else {
			failed := 0
			for _, port := range ports {
				n, err := strconv.Atoi(port)
				if err != nil || n < 1 || n > 65535 {
					failed++
					continue
				}
				if ctx.Err() != nil {
					failed++
					continue
				}
				data, err := dial(net.JoinHostPort(host, port))
				if err != nil {
					failed++
				} else {
					_ = data.Close()
				}
			}
			if failed > 0 {
				add("data_ports", "fail", strconv.Itoa(failed)+" 个已分配数据端口不可达")
			} else {
				add("data_ports", "pass", strconv.Itoa(len(ports))+" 个已分配数据端口可达")
			}
		}
	}
	add("targets", "skip", "目标由 Server Web 配置；实际目标可达性在建立转发时验证")
	return report
}

func write(conn net.Conn, kind byte, id uint64, fields ...string) error {
	body, err := wp.PutStrings(fields...)
	if err != nil {
		return err
	}
	frame, err := wp.Encode(wp.Frame{Type: kind, RequestID: id, Body: body})
	if err != nil {
		return err
	}
	for len(frame) > 0 {
		n, err := conn.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("short write")
		}
		frame = frame[n:]
	}
	return nil
}
