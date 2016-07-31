// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package rbac

/////////////// group

type testGroup struct {
	id string
}

func (r *testGroup) RoleID() string {
	return "group-" + r.id
}

func (r *testGroup) Parents() []Roler {
	return nil
}

///////////////// user

type testUser struct {
	id     string
	parent Roler
}

func (r *testUser) RoleID() string {
	return "user-" + r.id
}

func (r *testUser) Parents() []Roler {
	return []Roler{r.parent}
}

/////////////// resource

type testResource struct {
	id string
}

func (r *testResource) ResourceID() string {
	return "resource-" + r.id
}
