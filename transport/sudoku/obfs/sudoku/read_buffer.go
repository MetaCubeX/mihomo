package sudoku

import "bufio"

func peekBufferedChunk(reader *bufio.Reader) ([]byte, error) {
	if reader.Buffered() == 0 {
		if _, err := reader.Peek(1); err != nil {
			return nil, err
		}
	}
	chunk, err := reader.Peek(reader.Buffered())
	return chunk, err
}
