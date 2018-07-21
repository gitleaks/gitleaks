package goblin

import (
	"fmt"
	"reflect"
	"strings"
)

// Assertion represents a fact stated about a source object. It contains the source object and function to call
type Assertion struct {
	src  interface{}
	fail func(interface{})
}

func objectsAreEqual(a, b interface{}) bool {
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		return false
	}

	if reflect.DeepEqual(a, b) {
		return true
	}

	if fmt.Sprintf("%#v", a) == fmt.Sprintf("%#v", b) {
		return true
	}

	return false
}

func formatMessages(messages ...string) string {
	if len(messages) > 0 {
		return ", " + strings.Join(messages, " ")
	}
	return ""
}

// Eql is a shorthand alias of Equal for convenience
func (a *Assertion) Eql(dst interface{}) {
	a.Equal(dst)
}

// Equal takes a destination object and asserts that a source object and
// destination object are equal to one another. It will fail the assertion and
// print a corresponding message if the objects are not equivalent.
func (a *Assertion) Equal(dst interface{}) {
	if !objectsAreEqual(a.src, dst) {
		a.fail(fmt.Sprintf("%#v %s %#v", a.src, "does not equal", dst))
	}
}

// IsTrue asserts that a source is equal to true. Optional messages can be
// provided for inclusion in the displayed message if the assertion fails. It
// will fail the assertion if the source does not resolve to true.
func (a *Assertion) IsTrue(messages ...string) {
	if !objectsAreEqual(a.src, true) {
		message := fmt.Sprintf("%v %s%s", a.src, "expected false to be truthy", formatMessages(messages...))
		a.fail(message)
	}
}

// IsFalse asserts that a source is equal to false. Optional messages can be
// provided for inclusion in the displayed message if the assertion fails. It
// will fail the assertion if the source does not resolve to false.
func (a *Assertion) IsFalse(messages ...string) {
	if !objectsAreEqual(a.src, false) {
		message := fmt.Sprintf("%v %s%s", a.src, "expected true to be falsey", formatMessages(messages...))
		a.fail(message)
	}
}
