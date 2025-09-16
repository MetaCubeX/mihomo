package queue

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestQueuePut tests the Put method of Queue
func TestQueuePut(t *testing.T) {
	// Initialize a new queue
	q := New[int](10)

	// Test putting a single item
	q.Put(1)
	assert.Equal(t, int64(1), q.Len(), "Queue length should be 1 after putting one item")

	// Test putting multiple items
	q.Put(2, 3, 4)
	assert.Equal(t, int64(4), q.Len(), "Queue length should be 4 after putting three more items")

	// Test putting zero items (should not change queue)
	q.Put()
	assert.Equal(t, int64(4), q.Len(), "Queue length should remain unchanged when putting zero items")
}

// TestQueuePop tests the Pop method of Queue
func TestQueuePop(t *testing.T) {
	// Initialize a new queue with items
	q := New[int](10)
	q.Put(1, 2, 3)

	// Test popping items in FIFO order
	item := q.Pop()
	assert.Equal(t, 1, item, "First item popped should be 1")
	assert.Equal(t, int64(2), q.Len(), "Queue length should be 2 after popping one item")

	item = q.Pop()
	assert.Equal(t, 2, item, "Second item popped should be 2")
	assert.Equal(t, int64(1), q.Len(), "Queue length should be 1 after popping two items")

	item = q.Pop()
	assert.Equal(t, 3, item, "Third item popped should be 3")
	assert.Equal(t, int64(0), q.Len(), "Queue length should be 0 after popping all items")
}

// TestQueuePopEmpty tests the Pop method on an empty queue
func TestQueuePopEmpty(t *testing.T) {
	// Initialize a new empty queue
	q := New[int](0)

	// Test popping from an empty queue
	item := q.Pop()
	assert.Equal(t, 0, item, "Popping from an empty queue should return the zero value")
	assert.Equal(t, int64(0), q.Len(), "Queue length should remain 0 after popping from an empty queue")
}

// TestQueueLast tests the Last method of Queue
func TestQueueLast(t *testing.T) {
	// Initialize a new queue with items
	q := New[int](10)
	q.Put(1, 2, 3)

	// Test getting the last item
	item := q.Last()
	assert.Equal(t, 3, item, "Last item should be 3")
	assert.Equal(t, int64(3), q.Len(), "Queue length should remain unchanged after calling Last")

	// Test Last on an empty queue
	emptyQ := New[int](0)
	emptyItem := emptyQ.Last()
	assert.Equal(t, 0, emptyItem, "Last on an empty queue should return the zero value")
}

// TestQueueCopy tests the Copy method of Queue
func TestQueueCopy(t *testing.T) {
	// Initialize a new queue with items
	q := New[int](10)
	q.Put(1, 2, 3)

	// Test copying the queue
	copy := q.Copy()
	assert.Equal(t, 3, len(copy), "Copy should have the same number of items as the original queue")
	assert.Equal(t, 1, copy[0], "First item in copy should be 1")
	assert.Equal(t, 2, copy[1], "Second item in copy should be 2")
	assert.Equal(t, 3, copy[2], "Third item in copy should be 3")

	// Verify that modifying the copy doesn't affect the original queue
	copy[0] = 99
	assert.Equal(t, 1, q.Pop(), "Original queue should not be affected by modifying the copy")
}

// TestQueueLen tests the Len method of Queue
func TestQueueLen(t *testing.T) {
	// Initialize a new empty queue
	q := New[int](10)
	assert.Equal(t, int64(0), q.Len(), "New queue should have length 0")

	// Add items and check length
	q.Put(1, 2)
	assert.Equal(t, int64(2), q.Len(), "Queue length should be 2 after putting two items")

	// Remove an item and check length
	q.Pop()
	assert.Equal(t, int64(1), q.Len(), "Queue length should be 1 after popping one item")
}

// TestQueueNew tests the New constructor
func TestQueueNew(t *testing.T) {
	// Test creating a new queue with different hints
	q1 := New[int](0)
	assert.NotNil(t, q1, "New queue should not be nil")
	assert.Equal(t, int64(0), q1.Len(), "New queue should have length 0")

	q2 := New[int](10)
	assert.NotNil(t, q2, "New queue should not be nil")
	assert.Equal(t, int64(0), q2.Len(), "New queue should have length 0")

	// Test with a different type
	q3 := New[string](5)
	assert.NotNil(t, q3, "New queue should not be nil")
	assert.Equal(t, int64(0), q3.Len(), "New queue should have length 0")
}

// TestQueueConcurrency tests the concurrency safety of Queue
func TestQueueConcurrency(t *testing.T) {
	// Initialize a new queue
	q := New[int](100)

	// Number of goroutines and operations
	goroutines := 10
	operations := 100

	// Wait group to synchronize goroutines
	wg := sync.WaitGroup{}
	wg.Add(goroutines * 2) // For both producers and consumers

	// Start producer goroutines
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				q.Put(id*operations + j)
				// Small sleep to increase chance of race conditions
				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	// Start consumer goroutines
	consumed := make(chan int, goroutines*operations)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				// Try to pop an item, but don't block if queue is empty
				// Use a mutex to avoid race condition between Len() check and Pop()
				q.lock.Lock()
				if len(q.items) > 0 {
					item := q.items[0]
					q.items = q.items[1:]
					q.lock.Unlock()
					consumed <- item
				} else {
					q.lock.Unlock()
				}
				// Small sleep to increase chance of race conditions
				time.Sleep(time.Microsecond)
			}
		}()
	}

	// Wait for all goroutines to finish
	wg.Wait()
	// Close the consumed channel
	close(consumed)

	// Count the number of consumed items
	consumedCount := 0
	for range consumed {
		consumedCount++
	}

	// Check that the queue is in a consistent state
	totalItems := goroutines * operations
	remaining := int(q.Len())
	assert.Equal(t, totalItems, consumedCount+remaining, "Total items should equal consumed items plus remaining items")
}

// TestQueueWithDifferentTypes tests the Queue with different types
func TestQueueWithDifferentTypes(t *testing.T) {
	// Test with string type
	qString := New[string](5)
	qString.Put("hello", "world")
	assert.Equal(t, int64(2), qString.Len(), "Queue length should be 2")
	assert.Equal(t, "hello", qString.Pop(), "First item should be 'hello'")
	assert.Equal(t, "world", qString.Pop(), "Second item should be 'world'")

	// Test with struct type
	type Person struct {
		Name string
		Age  int
	}

	qStruct := New[Person](5)
	qStruct.Put(Person{Name: "Alice", Age: 30}, Person{Name: "Bob", Age: 25})
	assert.Equal(t, int64(2), qStruct.Len(), "Queue length should be 2")

	firstPerson := qStruct.Pop()
	assert.Equal(t, "Alice", firstPerson.Name, "First person's name should be 'Alice'")
	secondPerson := qStruct.Pop()
	assert.Equal(t, "Bob", secondPerson.Name, "Second person's name should be 'Bob'")
}
