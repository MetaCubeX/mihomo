package config

import (
	"encoding/json"

	"github.com/metacubex/mihomo/transport/xhttp"
)

type XhttpServer struct {
	Enable               bool              `yaml:"enable" json:"enable"`
	Listen               string            `yaml:"listen" json:"listen"`
	Host                 string            `yaml:"host" json:"host"`
	Path                 string            `yaml:"path" json:"path"`
	Mode                 string            `yaml:"mode" json:"mode"`
	HTTPVersion          string            `yaml:"http-version" json:"http-version"`
	Headers              map[string]string `yaml:"headers" json:"headers"`
	NoGRPCHeader         bool              `yaml:"no-grpc-header" json:"no-grpc-header"`
	NoSSEHeader          bool              `yaml:"no-sse-header" json:"no-sse-header"`
	XPaddingBytes        xhttp.Range       `yaml:"x-padding-bytes" json:"x-padding-bytes"`
	ScMaxEachPostBytes   xhttp.Range       `yaml:"sc-max-each-post-bytes" json:"sc-max-each-post-bytes"`
	ScMinPostsIntervalMs xhttp.Range       `yaml:"sc-min-posts-interval-ms" json:"sc-min-posts-interval-ms"`
	ScMaxBufferedPosts   xhttp.Range       `yaml:"sc-max-buffered-posts" json:"sc-max-buffered-posts"`
	ScStreamUpServerSecs xhttp.Range       `yaml:"sc-stream-up-server-secs" json:"sc-stream-up-server-secs"`
	DownloadSettings     *XhttpServer      `yaml:"download-settings,omitempty" json:"download-settings,omitempty"`
	Xmux                 XhttpXmuxConfig   `yaml:"xmux" json:"xmux"`
	Certificate          string            `yaml:"certificate" json:"certificate"`
	PrivateKey           string            `yaml:"private-key" json:"private-key"`
}

type XhttpXmuxConfig struct {
	MaxConcurrency   xhttp.Range `yaml:"max-concurrency" json:"max-concurrency"`
	MaxConnections   xhttp.Range `yaml:"max-connections" json:"max-connections"`
	CMaxReuseTimes   xhttp.Range `yaml:"c-max-reuse-times" json:"c-max-reuse-times"`
	HMaxRequestTimes xhttp.Range `yaml:"h-max-request-times" json:"h-max-request-times"`
	HMaxReusableSecs xhttp.Range `yaml:"h-max-reusable-secs" json:"h-max-reusable-secs"`
	HKeepAlivePeriod int64       `yaml:"h-keep-alive-period" json:"h-keep-alive-period"`
}

func (x XhttpServer) String() string {
	b, _ := json.Marshal(x)
	return string(b)
}
