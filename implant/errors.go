package main

import "sync"

var ERROR_QUEUE []string
var ERROR_QUEUE_MUTEX sync.Mutex

const MAX_ERROR_QUEUE = 10

func queueError(tag string) {
	ERROR_QUEUE_MUTEX.Lock()
	defer ERROR_QUEUE_MUTEX.Unlock()
	if len(ERROR_QUEUE) < MAX_ERROR_QUEUE {
		ERROR_QUEUE = append(ERROR_QUEUE, tag)
	}
}

func drainErrors() []string {
	ERROR_QUEUE_MUTEX.Lock()
	defer ERROR_QUEUE_MUTEX.Unlock()
	if len(ERROR_QUEUE) == 0 {
		return nil
	}
	errs := ERROR_QUEUE
	ERROR_QUEUE = nil
	return errs
}

func attachErrors(res Result) Result {
	res.Errors = drainErrors()
	return res
}
