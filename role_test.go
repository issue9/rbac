// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package rbac

import (
	"testing"

	"github.com/issue9/assert"
)

func TestRole(t *testing.T) {
	a := assert.New(t)

	r := &role{id: "1"}

	// 不存在
	r.revoke("r1")
	r1, found := r.resources["r1"]
	a.False(found).False(r1)

	r.deny("r1")
	a.False(r.resources["r1"])

	r.allow("r1")
	a.True(r.resources["r1"])

	r.revoke("r1")
	r1, found = r.resources["r1"]
	a.False(found).False(r1)

	r.deny("r1")
	a.False(r.resources["r1"])

	r = &role{}
	r.allow("r2")
	a.True(r.resources["r2"])

	r.deny("r2")
	a.False(r.resources["r2"])
}
