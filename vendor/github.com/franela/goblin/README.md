Goblin
======

[![Build Status](https://travis-ci.org/franela/goblin.svg)](https://travis-ci.org/franela/goblin)
[![Go Reportcard](https://goreportcard.com/badge/github.com/franela/goblin)](https://goreportcard.com/report/github.com/franela/goblin)
[![GoDoc](https://godoc.org/github.com/franela/goblin?status.svg)](https://godoc.org/github.com/franela/goblin)
[![License](https://img.shields.io/github/license/franela/goblin.svg)](https://github.com/franela/goblin/blob/master/LICENSE.md)
[![Release](https://img.shields.io/github/release/franela/goblin.svg)](https://github.com/franela/goblin/releases/latest)


A [Mocha](http://mochajs.org/) like BDD testing framework written in Go that requires no additional dependencies. Requires no extensive documentation nor complicated steps to get it running.

![](https://github.com/marcosnils/goblin/blob/master/goblin_logo.jpg?raw=true)

Why Goblin?
-----------

Inspired by the flexibility and simplicity of Node BDD and frustrated by the
rigorousness of Go way of testing, we wanted to bring a new tool to
write self-describing and comprehensive code.



What do I get with it?
----------------------

- Run tests as usual with `go test`
- Colorful reports and beautiful syntax
- Preserve the exact same syntax and behaviour as Node's Mocha
- Nest as many `Describe` and `It` blocks as you want
- Use `Before`, `BeforeEach`, `After` and `AfterEach` for setup and teardown your tests
- No need to remember confusing parameters in `Describe` and `It` blocks
- Use a declarative and expressive language to write your tests
- Plug different assertion libraries
 - [Gomega](https://github.com/onsi/gomega) (supported so far)
- Skip your tests the same way as you would do in Mocha
- Automatic terminal support for colored outputs
- Two line setup is all you need to get up running



How do I use it?
----------------

Since ```go test``` is not currently extensive, you will have to hook Goblin to it. You do that by
adding a single test method in your test file. All your goblin tests will be implemented inside this function.

```go
package foobar

import (
    "testing"
    . "github.com/franela/goblin"
)

func Test(t *testing.T) {
    g := Goblin(t)
    g.Describe("Numbers", func() {
        // Passing Test
        g.It("Should add two numbers ", func() {
            g.Assert(1+1).Equal(2)
        })
        // Failing Test
        g.It("Should match equal numbers", func() {
            g.Assert(2).Equal(4)
        })
        // Pending Test
        g.It("Should substract two numbers")
        // Excluded Test
        g.XIt("Should add two numbers ", func() {
            g.Assert(3+1).Equal(4)
        })
    })
}
```

Ouput will be something like:

![](https://github.com/marcosnils/goblin/blob/master/goblin_output.png?raw=true)

Nice and easy, right?

Can I do asynchronous tests?
----------------------------

Yes! Goblin will help you to test asynchronous things, like goroutines, etc. You just need to add a ```done``` parameter to the handler function of your ```It```. This handler function should be called when your test passes.

```go
  ...
  g.Describe("Numbers", func() {
      g.It("Should add two numbers asynchronously", func(done Done) {
          go func() {
              g.Assert(1+1).Equal(2)
              done()
          }()
      })
  })
  ...
```

Goblin will wait for the ```done``` call, a ```Fail``` call or any false assertion.

How do I use it with Gomega?
----------------------------

Gomega is a nice assertion framework. But it doesn't provide a nice way to hook it to testing frameworks. It should just panic instead of requiring a fail function. There is an issue about that [here](https://github.com/onsi/gomega/issues/5).
While this is being discussed and hopefully fixed, the way to use Gomega with Goblin is:

```go
package foobar

import (
    "testing"
    . "github.com/franela/goblin"
    . "github.com/onsi/gomega"
)

func Test(t *testing.T) {
    g := Goblin(t)

    //special hook for gomega
    RegisterFailHandler(func(m string, _ ...int) { g.Fail(m) })

    g.Describe("lala", func() {
        g.It("lslslslsls", func() {
            Expect(1).To(Equal(10))
        })
    })
}
```


FAQ
----

### How do I run specific tests?

If `-goblin.run=$REGES` is supplied to the `go test` command then only tests that match the supplied regex will run


Contributing
-----

We do have a couple of [issues](https://github.com/franela/goblin/issues) pending.  Feel free to contribute and send us PRs (with tests please :smile:).

Special Thanks
------------

Special thanks to [Leandro Reox](https://github.com/leandroreox) (Leitan) for the goblin logo.
