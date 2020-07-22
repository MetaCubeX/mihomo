package obfs

func init() {
	register("http_post", newHTTPPost)
}

func newHTTPPost(b *Base) Obfs {
	return &httpObfs{Base: b, post: true}
}
