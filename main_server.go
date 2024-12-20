//go:build !clientonly && !windows
// +build !clientonly,!windows

//
// Copyright (c) SAS Institute Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

// Server and server-adjacent commands
import (
	_ "github.com/sassoftware/relic/v8/cmdline/auditor"
	_ "github.com/sassoftware/relic/v8/cmdline/notarycmd"
	_ "github.com/sassoftware/relic/v8/cmdline/servecmd"
	_ "github.com/sassoftware/relic/v8/cmdline/workercmd"
)
