// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021-2023 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package main_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/assertstest"
	"github.com/snapcore/snapd/asserts/signtool"
	cmdsnap "github.com/snapcore/snapd/cmd/snap"
	"github.com/snapcore/snapd/image"
	"github.com/snapcore/snapd/seed/seedwriter"
	"github.com/snapcore/snapd/snap"
)

type SnapPrepareImageSuite struct {
	BaseSnapSuite
}

var _ = Suite(&SnapPrepareImageSuite{})

var (
	defaultPrivKey, _ = assertstest.GenerateKey(752)
	altPrivKey, _     = assertstest.GenerateKey(752)
)

type fakeKeyMgr struct {
	defaultKey asserts.PrivateKey
	altKey     asserts.PrivateKey
}

func (f *fakeKeyMgr) Put(privKey asserts.PrivateKey) error { return nil }
func (f *fakeKeyMgr) Get(keyID string) (asserts.PrivateKey, error) {
	switch keyID {
	case f.defaultKey.PublicKey().ID():
		return f.defaultKey, nil
	case f.altKey.PublicKey().ID():
		return f.altKey, nil
	default:
		return nil, fmt.Errorf("Could not find key pair with ID %q", keyID)
	}
}

func (f *fakeKeyMgr) GetByName(keyName string) (asserts.PrivateKey, error) {
	switch keyName {
	case "default":
		return f.defaultKey, nil
	case "alt":
		return f.altKey, nil
	default:
		return nil, fmt.Errorf("Could not find key pair with name %q", keyName)
	}
}

func (f *fakeKeyMgr) Delete(keyID string) error                { return nil }
func (f *fakeKeyMgr) Export(keyName string) ([]byte, error)    { return nil, nil }
func (f *fakeKeyMgr) List() ([]asserts.ExternalKeyInfo, error) { return nil, nil }
func (f *fakeKeyMgr) DeleteByName(keyName string) error        { return nil }

func (s *SnapPrepareImageSuite) TestPrepareImageCore(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	keyMgr := &fakeKeyMgr{defaultPrivKey, altPrivKey}
	restoreGetKeypairMgr := cmdsnap.MockGetKeypairManager(func() (signtool.KeypairManager, error) {
		return keyMgr, nil
	})
	defer restoreGetKeypairMgr()

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "model", "prepare-dir"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		ModelFile:      "model",
		PrepareDir:     "prepare-dir",
		PreseedSignKey: defaultPrivKey,
	})
}

func (s *SnapPrepareImageSuite) TestPrepareImageClassic(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	keyMgr := &fakeKeyMgr{defaultPrivKey, altPrivKey}
	restoreGetKeypairMgr := cmdsnap.MockGetKeypairManager(func() (signtool.KeypairManager, error) {
		return keyMgr, nil
	})
	defer restoreGetKeypairMgr()

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "--classic", "model", "prepare-dir"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		Classic:        true,
		ModelFile:      "model",
		PrepareDir:     "prepare-dir",
		PreseedSignKey: defaultPrivKey,
	})
}

func (s *SnapPrepareImageSuite) TestPrepareImageClassicArch(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	keyMgr := &fakeKeyMgr{defaultPrivKey, altPrivKey}
	restoreGetKeypairMgr := cmdsnap.MockGetKeypairManager(func() (signtool.KeypairManager, error) {
		return keyMgr, nil
	})
	defer restoreGetKeypairMgr()

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "--classic", "--arch", "i386", "model", "prepare-dir"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		Classic:        true,
		Architecture:   "i386",
		ModelFile:      "model",
		PrepareDir:     "prepare-dir",
		PreseedSignKey: defaultPrivKey,
	})
}

func (s *SnapPrepareImageSuite) TestPrepareImageClassicWideCohort(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	keyMgr := &fakeKeyMgr{defaultPrivKey, altPrivKey}
	restoreGetKeypairMgr := cmdsnap.MockGetKeypairManager(func() (signtool.KeypairManager, error) {
		return keyMgr, nil
	})
	defer restoreGetKeypairMgr()

	os.Setenv("UBUNTU_STORE_COHORT_KEY", "is-six-centuries")

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "--classic", "model", "prepare-dir"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		Classic:        true,
		WideCohortKey:  "is-six-centuries",
		ModelFile:      "model",
		PrepareDir:     "prepare-dir",
		PreseedSignKey: defaultPrivKey,
	})

	os.Unsetenv("UBUNTU_STORE_COHORT_KEY")
}

func (s *SnapPrepareImageSuite) TestPrepareImageExtraSnaps(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	keyMgr := &fakeKeyMgr{defaultPrivKey, altPrivKey}
	restoreGetKeypairMgr := cmdsnap.MockGetKeypairManager(func() (signtool.KeypairManager, error) {
		return keyMgr, nil
	})
	defer restoreGetKeypairMgr()

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "model", "prepare-dir", "--channel", "candidate", "--snap", "foo", "--snap", "bar=t/edge", "--snap", "local.snap", "--extra-snaps", "local2.snap", "--extra-snaps", "store-snap"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		ModelFile:      "model",
		Channel:        "candidate",
		PrepareDir:     "prepare-dir",
		Snaps:          []string{"foo", "bar", "local.snap", "local2.snap", "store-snap"},
		SnapChannels:   map[string]string{"bar": "t/edge"},
		PreseedSignKey: defaultPrivKey,
	})
}

func (s *SnapPrepareImageSuite) TestPrepareImageCustomize(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	keyMgr := &fakeKeyMgr{defaultPrivKey, altPrivKey}
	restoreGetKeypairMgr := cmdsnap.MockGetKeypairManager(func() (signtool.KeypairManager, error) {
		return keyMgr, nil
	})
	defer restoreGetKeypairMgr()

	tmpdir := c.MkDir()
	customizeFile := filepath.Join(tmpdir, "custo.json")
	err := ioutil.WriteFile(customizeFile, []byte(`{
  "console-conf": "disabled",
  "cloud-init-user-data": "cloud-init-user-data"
}`), 0644)
	c.Assert(err, IsNil)

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "model", "prepare-dir", "--customize", customizeFile})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		ModelFile:      "model",
		PrepareDir:     "prepare-dir",
		PreseedSignKey: defaultPrivKey,
		Customizations: image.Customizations{
			ConsoleConf:       "disabled",
			CloudInitUserData: "cloud-init-user-data",
		},
	})
}

func (s *SnapPrepareImageSuite) TestReadSeedManifest(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	var readManifestCalls int
	r = cmdsnap.MockSeedWriterReadManifest(func(manifestFile string) (*seedwriter.Manifest, error) {
		readManifestCalls++
		c.Check(manifestFile, Equals, "seed.manifest")
		return seedwriter.MockManifest(map[string]*seedwriter.ManifestSnapRevision{"snapd": {SnapName: "snapd", Revision: snap.R(100)}}, nil, nil, nil), nil
	})
	defer r()

	keyMgr := &fakeKeyMgr{defaultPrivKey, altPrivKey}
	restoreGetKeypairMgr := cmdsnap.MockGetKeypairManager(func() (signtool.KeypairManager, error) {
		return keyMgr, nil
	})
	defer restoreGetKeypairMgr()

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "model", "prepare-dir", "--revisions", "seed.manifest"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(readManifestCalls, Equals, 1)
	c.Check(opts, DeepEquals, &image.Options{
		ModelFile:      "model",
		PrepareDir:     "prepare-dir",
		PreseedSignKey: defaultPrivKey,
		SeedManifest:   seedwriter.MockManifest(map[string]*seedwriter.ManifestSnapRevision{"snapd": {SnapName: "snapd", Revision: snap.R(100)}}, nil, nil, nil),
	})
}

func (s *SnapPrepareImageSuite) TestPrepareImagePreseedArgError(c *C) {
	_, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "--preseed-sign-key", "alt", "model", "prepare-dir"})
	c.Assert(err, ErrorMatches, `--preseed-sign-key cannot be used without --preseed`)
}

func (s *SnapPrepareImageSuite) TestPrepareImagePreseed(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	keyMgr := &fakeKeyMgr{defaultPrivKey, altPrivKey}
	restoreGetKeypairMgr := cmdsnap.MockGetKeypairManager(func() (signtool.KeypairManager, error) {
		return keyMgr, nil
	})
	defer restoreGetKeypairMgr()

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "--preseed", "--preseed-sign-key", "alt", "--apparmor-features-dir", "aafeatures-dir", "--sysfs-overlay", "sys-overlay", "model", "prepare-dir"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		ModelFile:                 "model",
		PrepareDir:                "prepare-dir",
		Preseed:                   true,
		PreseedSignKey:            altPrivKey,
		SysfsOverlay:              "sys-overlay",
		AppArmorKernelFeaturesDir: "aafeatures-dir",
	})
}

func (s *SnapPrepareImageSuite) TestPrepareImageWriteRevisions(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	keyMgr := &fakeKeyMgr{defaultPrivKey, altPrivKey}
	restoreGetKeypairMgr := cmdsnap.MockGetKeypairManager(func() (signtool.KeypairManager, error) {
		return keyMgr, nil
	})
	defer restoreGetKeypairMgr()

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "model", "prepare-dir", "--write-revisions"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		ModelFile:        "model",
		PrepareDir:       "prepare-dir",
		PreseedSignKey:   defaultPrivKey,
		SeedManifestPath: "./seed.manifest",
	})

	rest, err = cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "model", "prepare-dir", "--write-revisions=/tmp/seed.manifest"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		ModelFile:        "model",
		PrepareDir:       "prepare-dir",
		PreseedSignKey:   defaultPrivKey,
		SeedManifestPath: "/tmp/seed.manifest",
	})
}
