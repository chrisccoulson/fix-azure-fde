// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/canonical/go-tpm2"
	"github.com/chrisccoulson/fix-azure-fde/luks2"
	"github.com/snapcore/secboot"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
	"golang.org/x/sys/unix"
)

const sealedKeyPath = "/boot/efi/device/fde/cloudimg-rootfs.sealed-key"

func determineLUKS2ContainerPath() (string, error) {
	fmt.Println("* Determing LUKS2 container path for rootfs")

	var rootSt unix.Stat_t
	if err := unix.Stat("/", &rootSt); err != nil {
		return "", fmt.Errorf("cannot stat /: %w", err)
	}

	dmSysfsPath, err := filepath.EvalSymlinks(filepath.Join("/sys/dev/block", fmt.Sprintf("%d:%d", unix.Major(rootSt.Dev), unix.Minor(rootSt.Dev))))
	if err != nil {
		return "", fmt.Errorf("cannot resolve dm path for rootfs: %w", err)
	}
	fmt.Println("  dm sysfs path for rootfs:", dmSysfsPath)

	dmPath := filepath.Join("/dev", filepath.Base(dmSysfsPath))
	fmt.Println("  dm path for rootfs:", dmPath)

	cmd := exec.Command("dmsetup", "table", dmPath)
	table, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("cannot obtain dm table for rootfs: %w", err)
	}
	fmt.Println("  dm table for rootfs:", string(table))

	var (
		length uint
		keystr string
		major  uint32
		minor  uint32
	)

	// The string format here is "start length target cipher :keylen:keystr iv_offset major:minor"
	if _, err := fmt.Sscanf(string(table), "0 %d crypt aes-xts-plain64 :64:%s 0 %d:%d", &length, &keystr, &major, &minor); err != nil {
		return "", fmt.Errorf("cannot scan dmtable for rootfs: %w", err)
	}
	fmt.Printf("  LUKS2 device for rootfs: %d:%d\n", major, minor)

	majorStr := strconv.FormatUint(uint64(major), 10)
	minorStr := strconv.FormatUint(uint64(minor), 10)
	luks2SysfsPath, err := filepath.EvalSymlinks(filepath.Join("/sys/dev/block", fmt.Sprintf("%s:%s", majorStr, minorStr)))
	if err != nil {
		return "", fmt.Errorf("cannot resolve path for LUKS2 device: %w", err)
	}
	luks2Path := filepath.Join("/dev", filepath.Base(luks2SysfsPath))

	fmt.Println("  LUKS2 sysfs path for rootfs:", luks2SysfsPath)
	fmt.Println("  LUKS2 path for rootfs:", luks2Path)
	fmt.Println()

	return luks2Path, nil
}

func sanitizeLUKS2Container(path string) error {
	fmt.Println("* Performing sanity checks on LUKS2 container")

	hdr, err := luks2.ReadHeader(path, luks2.LockModeBlocking)
	if err != nil {
		return fmt.Errorf("cannot decode LUKS2 header: %w", err)
	}

	// 1) We have 2 keyslots:
	if len(hdr.Metadata.Keyslots) != 2 {
		return errors.New("there should only be 2 keyslots on an instance that hasn't been manually modified")
	}
	fmt.Println("  header has expected 2 keyslots")

	// 2) Keyslot 0 is populated
	slot, ok := hdr.Metadata.Keyslots[0]
	if !ok {
		return errors.New("keyslot 0 should be populated on an instance that hasn't been manually modified")
	}
	fmt.Println("  keyslot 0 is populated")

	// 3) Keyslot 0 is populated with the parameters supplied to cryptsetup reeencrypt by encrypt-cloud-image
	if slot.Type != "luks2" || slot.KeySize != 64 || slot.KDF.Type != luks2.KDFTypeArgon2i || slot.KDF.Time != 4 || slot.KDF.Memory != 32768 {
		return errors.New("keyslot 0 does not have the expected properties for an instance that hasn't been manually modified")
	}
	fmt.Println("  keyslot 0 has the properties that encrypt-cloud-image uses to configure the initial key slot")

	// 4) Keyslot 1 is populated, which should be the recovery keyslot although there's no metadata to be able to tell
	if _, ok := hdr.Metadata.Keyslots[1]; !ok {
		return errors.New("keyslot 1 is not populated as expected on an instance that hasn't been manually modified")
	}
	fmt.Println("  keyslot 1 is populated")
	fmt.Println()

	return nil
}

func askForRecoveryKey(path string) (secboot.RecoveryKey, error) {
	cmd := exec.Command(
		"systemd-ask-password",
		"--icon", "drive-harddisk",
		"--id", filepath.Base(os.Args[0])+":"+path,
		"Please enter recovery code for "+path)
	out := new(bytes.Buffer)
	cmd.Stdout = out
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return secboot.RecoveryKey{}, fmt.Errorf("cannot execute systemd-ask-password: %v", err)
	}
	result, err := out.ReadString('\n')
	if err != nil {
		// The only error returned from bytes.Buffer.ReadString is io.EOF.
		return secboot.RecoveryKey{}, errors.New("systemd-ask-password output is missing terminating newline")
	}
	password := strings.TrimRight(result, "\n")
	key, err := secboot.ParseRecoveryKey(password)
	if err != nil {
		return secboot.RecoveryKey{}, fmt.Errorf("cannot parse recovery key: %w", err)
	}

	return key, nil
}

func run() error {
	luks2Path, err := determineLUKS2ContainerPath()
	if err != nil {
		return fmt.Errorf("cannot determine LUKS2 container path for rootfs: %w", err)
	}

	if err := sanitizeLUKS2Container(luks2Path); err != nil {
		return fmt.Errorf("cannot sanitize LUKS2 container: %w", err)
	}

	recoveryKey, err := askForRecoveryKey(luks2Path)
	if err != nil {
		return fmt.Errorf("cannot obtain recovery key for LUKS2 container: %w", err)
	}

	// Make sure that keyslot 1 is the recovery key
	if err := luks2.CheckLUKS2Key(luks2Path, 1, recoveryKey[:]); err != nil {
		return fmt.Errorf("supplied recovery key is invalid for keyslot 1, which might mean manual modifications have been performed: %w", err)
	}
	fmt.Println("* Supplied recovery key matches keyslot 1")

	fmt.Println("* Creating new unlock key")
	var key [16]byte // This is 16 bytes in encrypt-cloud-image to handle older vTPM implementations that only permitted smaller key sizes.
	if _, err := rand.Read(key[:]); err != nil {
		return fmt.Errorf("cannot obtain unlock key: %w", err)
	}

	fmt.Println("* Deleting keyslot 0")
	if err := luks2.KillSlot(luks2Path, 0); err != nil {
		return fmt.Errorf("cannot delete keyslot 0: %w", err)
	}

	fmt.Println("* Adding new keyslot 0")
	if err := luks2.AddKey(luks2Path, recoveryKey[:], key[:], &luks2.AddKeyOptions{
		KDFOptions: luks2.KDFOptions{
			Type:            luks2.KDFTypeArgon2i,
			MemoryKiB:       32 * 1024,
			ForceIterations: 4,
		},
		Slot: 0,
	}); err != nil {
		return fmt.Errorf("cannot add new keyslot 0: %w", err)
	}

	// Create an invalid PCR profile and then let nullboot do the resealing
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = 0xff
	}
	pcrProfile := secboot_tpm2.NewPCRProtectionProfile()
	pcrProfile.AddPCRValue(tpm2.HashAlgorithmSHA256, 0, digest)

	params := secboot_tpm2.KeyCreationParams{
		PCRProfile:             pcrProfile,
		PCRPolicyCounterHandle: tpm2.HandleNull,
	}

	fmt.Println("* Connecting to TPM")
	tpm, err := secboot_tpm2.ConnectToDefaultTPM()
	if err != nil {
		return fmt.Errorf("cannot connect to TPM: %w", err)
	}
	defer tpm.Close()

	fmt.Println("* Sealing new key to TPM")
	authKey, err := secboot_tpm2.SealKeyToTPM(tpm, key[:], sealedKeyPath, &params)
	if err != nil {
		return fmt.Errorf("cannot seal new TPM key: %w", err)
	}

	var st unix.Stat_t
	if err := unix.Stat(luks2Path, &st); err != nil {
		return fmt.Errorf("cannot stat LUKS2 path: %w", err)
	}
	byPartUUIDDir, err := os.Open("/dev/disk/by-partuuid")
	if err != nil {
		return err
	}
	entries, err := byPartUUIDDir.ReadDir(0)
	if err != nil {
		return fmt.Errorf("cannot obtain partitions by UUID: %w", err)
	}

	addedKeyToKeyring := false
	for _, entry := range entries {
		path := filepath.Join(byPartUUIDDir.Name(), entry.Name())

		var st2 unix.Stat_t
		if err := unix.Stat(path, &st2); err != nil {
			return fmt.Errorf("cannot stat %s: %w", path, err)
		}
		if st.Rdev == st2.Rdev {
			fmt.Println("* Adding key to root user keyring for nullboot")
			if _, err := unix.AddKey("user", fmt.Sprintf("ubuntu-fde:%s:aux", path), authKey, -4); err != nil {
				return fmt.Errorf("cannot add key to root user keyring for nullboot: %w", err)
			}
			addedKeyToKeyring = true
			break
		}
	}
	if !addedKeyToKeyring {
		return errors.New("key required by nullboot not added to keyring")
	}

	cmd := exec.Command("nullbootctl")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot run nullbootctl: %w", err)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
