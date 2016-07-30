// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package rbac

/////////////// group

type testGroup struct {
	id string
}

func (r *testGroup) UniqueID() string {
	return "group-" + r.id
}

func (r *testGroup) Parents() []Roler {
	return nil
}

func (r *testGroup) IsAllowHook(resource Resourcer) int {
	return Continue
}

///////////////// user

type testUser struct {
	id     string
	parent Roler
}

func (r *testUser) UniqueID() string {
	return "user-" + r.id
}

func (r *testUser) Parents() []Roler {
	return []Roler{r.parent}
}

func (r *testUser) IsAllowHook(resource Resourcer) int {
	return Continue
}

/////////////// resource

type testResource struct {
	id string
}

func (r *testResource) UniqueID() string {
	return "resource-" + r.id
}
