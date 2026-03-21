package xsync

// LoadOrStoreFn returns the existing value for the key if
// present. Otherwise, it tries to compute the value using the
// provided function and, if successful, stores and returns
// the computed value. The loaded result is true if the value was
// loaded, or false if computed.
//
// This call locks a hash table bucket while the compute function
// is executed. It means that modifications on other entries in
// the bucket will be blocked until the valueFn executes. Consider
// this when the function includes long-running operations.
//
// Recovery this API and renamed from xsync/v3's LoadOrCompute.
// We unneeded support no-op (cancel) compute operation, it will only add complexity to existing code.
func (m *Map[K, V]) LoadOrStoreFn(key K, valueFn func() V) (actual V, loaded bool) {
	return m.doCompute(
		key,
		func(oldValue V, loaded bool) (V, ComputeOp) {
			if loaded {
				return oldValue, CancelOp
			}
			return valueFn(), UpdateOp
		},
		loadOrComputeOp,
		false,
	)
}
