package route

var (
	CtxKeyProxyName = contextKey("proxy name")
	CtxKeyProxy     = contextKey("proxy")
)

type contextKey string

func (c contextKey) String() string {
	return "clash context key " + string(c)
}
