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

// Commands and signers for the basic client only (pure Go, all OSes)

import (
	"runtime/debug"
	"strings"

	"github.com/sassoftware/relic/v8/cmdline/shared"
	"github.com/sassoftware/relic/v8/config"

	_ "github.com/sassoftware/relic/v8/cmdline/remotecmd"
	_ "github.com/sassoftware/relic/v8/cmdline/verify"

	_ "github.com/sassoftware/relic/v8/signers/apk"
	_ "github.com/sassoftware/relic/v8/signers/appmanifest"
	_ "github.com/sassoftware/relic/v8/signers/appx"
	_ "github.com/sassoftware/relic/v8/signers/cab"
	_ "github.com/sassoftware/relic/v8/signers/cat"
	_ "github.com/sassoftware/relic/v8/signers/cosign"
	_ "github.com/sassoftware/relic/v8/signers/deb"
	_ "github.com/sassoftware/relic/v8/signers/dmg"
	_ "github.com/sassoftware/relic/v8/signers/jar"
	_ "github.com/sassoftware/relic/v8/signers/macho"
	_ "github.com/sassoftware/relic/v8/signers/msi"
	_ "github.com/sassoftware/relic/v8/signers/pecoff"
	_ "github.com/sassoftware/relic/v8/signers/pgp"
	_ "github.com/sassoftware/relic/v8/signers/pkcs"
	_ "github.com/sassoftware/relic/v8/signers/ps"
	_ "github.com/sassoftware/relic/v8/signers/rpm"
	_ "github.com/sassoftware/relic/v8/signers/vsix"
	_ "github.com/sassoftware/relic/v8/signers/xap"
	_ "github.com/sassoftware/relic/v8/signers/xar"
	_ "github.com/sassoftware/relic/v8/signers/blob"
)

var (
	version = "unknown" // set this at link time
	commit  = "unknown" // set this at link time
)

func main() {
	if version != "unknown" {
		// normal CI compilation path
		config.Version = version
		config.Commit = commit
	} else if bi, ok := debug.ReadBuildInfo(); ok {
		// built from go module with `go install`
		if strings.HasPrefix(bi.Main.Version, "v") {
			config.Version = bi.Main.Version
			config.Commit = bi.Main.Sum
		}
	}

	config.UserAgent = "relic/" + config.Version
	shared.Main()
}
