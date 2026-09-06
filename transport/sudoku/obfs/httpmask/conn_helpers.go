/*
Copyright (C) 2026 by saba <contact me via issue>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
*/
package httpmask

import (
	"io"
)

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func tryCloseRead(target any) error {
	if closer, ok := target.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return nil
}

func tryCloseWrite(target any) error {
	if closer, ok := target.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	if closer, ok := target.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
