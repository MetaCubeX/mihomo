package script

/*
#include "Python.h"
*/
import "C"

//PyThreadState : https://docs.python.org/3/c-api/init.html#c.PyThreadState
type PyThreadState C.PyThreadState

//PyGILState is an opaque “handle” to the thread state when PyGILState_Ensure() was called, and must be passed to PyGILState_Release() to ensure Python is left in the same state
type PyGILState C.PyGILState_STATE

//PyEval_SaveThread : https://docs.python.org/3/c-api/init.html#c.PyEval_SaveThread
func PyEval_SaveThread() *PyThreadState {
	return (*PyThreadState)(C.PyEval_SaveThread())
}

//PyEval_RestoreThread : https://docs.python.org/3/c-api/init.html#c.PyEval_RestoreThread
func PyEval_RestoreThread(tstate *PyThreadState) {
	C.PyEval_RestoreThread((*C.PyThreadState)(tstate))
}

//PyThreadState_Get : https://docs.python.org/3/c-api/init.html#c.PyThreadState_Get
func PyThreadState_Get() *PyThreadState {
	return (*PyThreadState)(C.PyThreadState_Get())
}

//PyThreadState_Swap : https://docs.python.org/3/c-api/init.html#c.PyThreadState_Swap
func PyThreadState_Swap(tstate *PyThreadState) *PyThreadState {
	return (*PyThreadState)(C.PyThreadState_Swap((*C.PyThreadState)(tstate)))
}

//PyGILState_Ensure : https://docs.python.org/3/c-api/init.html#c.PyGILState_Ensure
func PyGILState_Ensure() PyGILState {
	return PyGILState(C.PyGILState_Ensure())
}

//PyGILState_Release : https://docs.python.org/3/c-api/init.html#c.PyGILState_Release
func PyGILState_Release(state PyGILState) {
	C.PyGILState_Release(C.PyGILState_STATE(state))
}

//PyGILState_GetThisThreadState : https://docs.python.org/3/c-api/init.html#c.PyGILState_GetThisThreadState
func PyGILState_GetThisThreadState() *PyThreadState {
	return (*PyThreadState)(C.PyGILState_GetThisThreadState())
}

//PyGILState_Check : https://docs.python.org/3/c-api/init.html#c.PyGILState_Check
func PyGILState_Check() bool {
	return C.PyGILState_Check() == 1
}
