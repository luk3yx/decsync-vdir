//
// decsync-vdir
// Copyright © 2022 by luk3yx
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

package main

import (
	"bufio"
	"bytes"
	cryptoRand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

type any = interface{}

var infoPath = []string{"info"}
var ErrNoDeviceName = errors.New("No device name specified (read-only mode)")
var safeFilenameRegex = regexp.MustCompile(`^[A-Za-z0-9\-_]+$`)

func isUnsafeFilename(fn string) bool {
	return safeFilenameRegex.Find([]byte(fn)) == nil
}

func assert(err error) {
	if err != nil {
		panic(err)
	}
}

func uuid4() string {
	var uuid [16]byte
	_, err := cryptoRand.Read(uuid[:])
	assert(err)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	s := fmt.Sprintf("%032x", uuid)
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[:8], s[8:12], s[12:16], s[16:20], s[20:])
}

// This code doesn't work exactly like libdecsync, it doesn't bother updating
// its own entry files with any new entries.
func getPathHash(path []string) string {
	if len(path) == 1 && path[0] == "info" {
		return "info"
	}
	var hash uint8
	for _, component := range path {
		var componentHash uint8
		for _, b := range []byte(component) {
			componentHash = componentHash*19 + b
		}
		hash = hash*199 + componentHash
	}
	return fmt.Sprintf("%02x", hash)
}

func pathEquals(p1, p2 []string) bool {
	if len(p1) != len(p2) {
		return false
	}

	for i, v1 := range p1 {
		if v1 != p2[i] {
			return false
		}
	}
	return true
}

func pathStartsWith(p1, p2 []string) bool {
	if len(p1) < len(p2) {
		return false
	}

	for i, v2 := range p2 {
		if v2 != p1[i] {
			return false
		}
	}
	return true
}

func isDir(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

type DecSyncFolder struct {
	directory     string
	deviceName    string
	lastActiveDay time.Time
}

type SyncEntry struct {
	deviceName   string
	Path         []string
	LastModified time.Time
	Key          any
	Value        any
}

const decsyncTimeFormat = "2006-01-02T15:04:05"

func (e *SyncEntry) UnmarshalJSON(data []byte) error {
	var dateStr string
	var arr = [4]any{&e.Path, &dateStr, &e.Key, &e.Value}
	err := json.Unmarshal(data, &arr)
	if err == nil {
		e.LastModified, err = time.Parse(decsyncTimeFormat, dateStr)
	}
	return err
}

func (e SyncEntry) MarshalJSON() ([]byte, error) {
	dateStr := e.LastModified.UTC().Format(decsyncTimeFormat)
	return json.Marshal([4]any{e.Path, dateStr, e.Key, e.Value})
}

func (d *DecSyncFolder) Exists() (bool, error) {
	return isDir(d.directory + "/v2")
}

func (d *DecSyncFolder) readAllEntries(path []string, callback func(SyncEntry)) error {
	deviceDirs, err := os.ReadDir(d.directory + "/v2")
	if err != nil {
		return err
	}

	hash := getPathHash(path)
	for _, dir := range deviceDirs {
		err = d.parseFile(dir.Name(), hash, callback)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}

func (d *DecSyncFolder) parseFile(deviceName, hash string, callback func(SyncEntry)) error {
	f, err := os.Open(d.directory + "/v2/" + deviceName + "/" + hash)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry SyncEntry
		if err = json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return err
		}
		entry.deviceName = deviceName
		callback(entry)
	}
	return nil
}

func insertEntryIfNewer(entries map[any]SyncEntry, entry SyncEntry) {
	curEntry := entries[entry.Key]
	if entry.LastModified.After(curEntry.LastModified) {
		entries[entry.Key] = entry
	}
}

// Iterates over everything starting with the path prefix
func (d *DecSyncFolder) Iter(pathPrefix []string, includeDeleted bool, callback func(SyncEntry) error) error {
	deviceDirs, err := os.ReadDir(d.directory + "/v2")
	if err != nil {
		return err
	}

	// Collect all the filenames that need to be searched
	hashes := make(map[string][]string)
	for _, dir := range deviceDirs {
		data, err := os.ReadFile(d.directory + "/v2/" + dir.Name() + "/sequences")
		if err != nil {
			return err
		}
		var sequences map[string]uint64
		if err = json.Unmarshal(data, &sequences); err != nil {
			return err
		}

		// Add every hash to the hashes list
		for hash := range sequences {
			hashes[hash] = append(hashes[hash], dir.Name())
		}
	}

	// Now read all entries one file at a time
	for hash, devicesWithHash := range hashes {
		// Create an entries map from all devices that have the file
		entries := make(map[any]SyncEntry)
		for _, deviceName := range devicesWithHash {
			err = d.parseFile(deviceName, hash, func(entry SyncEntry) {
				if pathStartsWith(entry.Path, pathPrefix) {
					insertEntryIfNewer(entries, entry)
				}
			})
			if err != nil {
				return err
			}
		}

		// Run the callbacks on this "batch" of entries
		for _, entry := range entries {
			// Don't process deleted entries
			if !includeDeleted && entry.Value == nil {
				continue
			}

			if err = callback(entry); err != nil {
				return err
			}
		}
	}

	return nil
}

// Gets all values in a path
func (d *DecSyncFolder) GetAll(path []string) (map[any]any, error) {
	entries := make(map[any]SyncEntry)
	err := d.readAllEntries(path, func(entry SyncEntry) {
		if pathEquals(entry.Path, path) {
			insertEntryIfNewer(entries, entry)
		}
	})
	if err != nil {
		return nil, err
	}

	values := make(map[any]any, len(entries))
	for k, entry := range entries {
		if entry.Value != nil {
			values[k] = entry.Value
		}
	}
	return values, nil
}

// Gets one value from a path
func (d *DecSyncFolder) Get(path []string, key any) (any, error) {
	var curEntry SyncEntry
	err := d.readAllEntries(path, func(entry SyncEntry) {
		if pathEquals(entry.Path, path) && key == entry.Key && entry.LastModified.After(curEntry.LastModified) {
			curEntry = entry
		}
	})
	return curEntry.Value, err
}

// Gets the name (or an empty string on error)
func (d *DecSyncFolder) Name() string {
	name, err := d.Get(infoPath, "name")
	if err != nil {
		return ""
	}
	nameStr, _ := name.(string)
	return nameStr
}

func writeIfNotExist(dir, fn string, content []byte) error {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	f, err := os.OpenFile(dir+"/"+fn, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	_, err = f.Write(content)
	return err
}

func (d *DecSyncFolder) writeDeviceInfo() error {
	if d.deviceName == "" {
		return ErrNoDeviceName
	}

	// Create the "local" directory
	localDeviceDir := d.directory + "/local/" + d.deviceName
	if err := os.MkdirAll(localDeviceDir, 0750); err != nil {
		return err
	}

	// If the last-active value was already updated today then don't bother
	// updating it again
	utcNow := time.Now().UTC()
	utcToday := utcNow.Truncate(24 * time.Hour)
	if d.lastActiveDay.Equal(utcToday) {
		return nil
	}

	// Write to the "info" file
	lastActiveStr := utcToday.Format("2006-01-02")
	data, err := json.Marshal(map[string]any{
		"version":           2,
		"last-active":       lastActiveStr,
		"supported-version": 2,
	})
	assert(err)

	data = append(data, '\n')
	if err = os.WriteFile(localDeviceDir+"/info", data, 0640); err != nil {
		return err
	}

	// Make sure our /v2/ directory exists
	if err = os.MkdirAll(d.directory+"/v2/"+d.deviceName, 0750); err != nil {
		return err
	}

	// Update the "last active" and "supported version" entries
	err = d.insertEntryRaw(SyncEntry{
		Path:         infoPath,
		LastModified: utcNow,
		Key:          "last-active-" + d.deviceName,
		Value:        lastActiveStr,
	})
	if err == nil {
		err = d.insertEntryRaw(SyncEntry{
			Path:         infoPath,
			LastModified: utcNow,
			Key:          "supported-version-" + d.deviceName,
			Value:        2,
		})

		if err == nil {
			d.lastActiveDay = utcToday
		}
	}
	return err
}

func atomicWriteFile(fn string, data []byte) error {
	tmpFn := fn + ".tmp"
	if err := os.WriteFile(tmpFn, data, 0640); err != nil {
		return err
	}
	return os.Rename(tmpFn, fn)
}

// Sets a value
func (d *DecSyncFolder) Set(path []string, key, value any) error {
	return d.InsertEntry(SyncEntry{
		Path:         path,
		LastModified: time.Now(),
		Key:          key,
		Value:        value,
	})
}

func (d *DecSyncFolder) InsertEntry(newEntry SyncEntry) error {
	if err := d.writeDeviceInfo(); err != nil {
		return err
	}
	return d.insertEntryRaw(newEntry)
}

func (d *DecSyncFolder) insertEntryRaw(newEntry SyncEntry) error {
	// Read existing entries
	entries := make([]SyncEntry, 0, 1)
	hash := getPathHash(newEntry.Path)
	err := d.parseFile(d.deviceName, hash, func(entry SyncEntry) {
		if !pathEquals(newEntry.Path, entry.Path) || newEntry.Key != entry.Key {
			entries = append(entries, entry)
		}
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Read the sequences file
	v2Dir := d.directory + "/v2/" + d.deviceName + "/"
	sequencesFn := v2Dir + "sequences"
	data, err := os.ReadFile(sequencesFn)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		data = []byte("{}")
	}

	// Increment the modified hash
	var sequences map[string]uint64
	if err = json.Unmarshal(data, &sequences); err != nil {
		return err
	}
	sequences[hash]++

	// Write the sequences file back
	// This is done before writing the hash file because it's probably safe to
	// increment the sequences number without changing anything
	data, err = json.Marshal(sequences)
	assert(err)
	if err = atomicWriteFile(sequencesFn, append(data, '\n')); err != nil {
		return err
	}

	// Add new entry
	entries = append(entries, newEntry)

	// Write all the entries back as JSON
	var b bytes.Buffer
	for _, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		b.Write(data)
		b.WriteByte('\n')
	}

	return atomicWriteFile(v2Dir+hash, b.Bytes())
}

// For handling contacts/calendars
func (d *DecSyncFolder) GetResource(uid string) (string, error) {
	resource, err := d.Get([]string{"resources", uid}, nil)
	if err != nil || resource == nil {
		return "", err
	} else if resourceStr, ok := resource.(string); ok {
		return resourceStr, nil
	}
	return "", errors.New("Invalid resource type")
}

func (d *DecSyncFolder) UpdateResource(uid string, newData string, ts time.Time) error {
	return d.InsertEntry(SyncEntry{
		Path:         []string{"resources", uid},
		LastModified: ts,
		Key:          nil,
		Value:        newData,
	})
}

func (d *DecSyncFolder) DeleteResource(uid string) error {
	return d.Set([]string{"resources", uid}, nil, nil)
}

func (d *DecSyncFolder) CreateResource(data string, ts time.Time) (string, error) {
	uid := uuid4()
	return uid, d.UpdateResource(uid, data, ts)
}

func (d *DecSyncFolder) IterResources(includeDeleted bool, callback func(string, string, time.Time) error) error {
	return d.Iter([]string{"resources"}, includeDeleted, func(entry SyncEntry) error {
		if entry.Key != nil {
			return nil
		}
		data, ok := entry.Value.(string)
		if !ok && entry.Value != nil {
			return errors.New("Invalid resource type")
		}
		return callback(entry.Path[1], data, entry.LastModified)
	})
}

func getVcardUID(reader io.Reader) (string, error) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		if bytes.HasPrefix(scanner.Bytes(), []byte("UID:")) {
			return string(scanner.Bytes()[4:]), nil
		}
	}
	return "", scanner.Err()
}

type uidToPathMap struct {
	m             map[string]string
	local         map[string]struct{}
	vdir          string
	fileExtension string
}

func (m uidToPathMap) addFile(vdirFile string) error {
	f, err := os.Open(vdirFile)
	if err != nil {
		return err
	}
	defer f.Close()
	uid, err := getVcardUID(f)
	if err == nil {
		if uid == "" {
			return errors.New("Could not read UID from " + vdirFile)
		} else if otherFile, exists := m.m[uid]; exists {
			return fmt.Errorf("Files %q and %q have the same UID", vdirFile, otherFile)
		}
		m.m[uid] = vdirFile
		m.local[uid] = struct{}{}
	}
	return err
}

func (m uidToPathMap) getPath(uid string) string {
	if path, ok := m.m[uid]; ok {
		return path
	} else if isUnsafeFilename(uid) {
		uid = uuid4()
	}
	return m.vdir + uid + m.fileExtension
}

func SyncVdir(sync *DecSyncFolder, vdir, fileExtension string) error {
	if !strings.HasSuffix(vdir, "/") {
		vdir += "/"
	}
	if fileExtension != "" && (fileExtension[0] != '.' || isUnsafeFilename(fileExtension[1:])) {
		return fmt.Errorf("Invalid file extension: %q", fileExtension)
	}

	if err := os.MkdirAll(vdir, 0750); err != nil {
		return err
	}

	m := uidToPathMap{
		m:             make(map[string]string),
		local:         make(map[string]struct{}),
		vdir:          vdir,
		fileExtension: fileExtension,
	}
	files, err := os.ReadDir(vdir)
	if err != nil {
		return err
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), fileExtension) {
			continue
		}
		if err = m.addFile(vdir + file.Name()); err != nil {
			return err
		}
	}

	// Sync contacts that exist on DecSync
	err = sync.IterResources(true, func(uid, syncData string, syncModified time.Time) error {
		if isUnsafeFilename(uid) {
			return errors.New("UUID is not a safe filename")
		}

		// The file was "seen" by DecSync so it isn't local
		delete(m.local, uid)

		vdirFile := m.getPath(uid)
		info, err := os.Stat(vdirFile)
		var vdirModified time.Time
		if err == nil {
			vdirModified = info.ModTime().Truncate(time.Second)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		} else if syncData == "" {
			// fmt.Println("Deleted on both sides: " + vdirFile)
			return nil
		}

		if syncModified.Before(vdirModified) {
			// vdir → DecSync
			fmt.Println("Updating DecSync: "+vdirFile, syncModified, vdirModified)
			content, err := os.ReadFile(vdirFile)
			if err != nil {
				return err
			}
			return sync.UpdateResource(uid, string(content), vdirModified)
		} else if vdirModified.Before(syncModified) {
			// DecSync → vdir
			// fmt.Println("Updating vdir: "+vdirFile, syncModified, vdirModified)
			if syncData == "" {
				return os.Remove(vdirFile)
			}
			err = atomicWriteFile(vdirFile, []byte(syncData))
			if err == nil {
				err = os.Chtimes(vdirFile, time.Now(), syncModified)
			}
			return err
		} else {
			// fmt.Println("Not modified: " + vdirFile)
			return nil
		}
	})

	for uid := range m.local {
		vdirFile, ok := m.m[uid]
		if !ok {
			panic("Unreachable code")
		}

		fmt.Println("Creating on DecSync: " + vdirFile)
		info, err := os.Stat(vdirFile)
		if err != nil {
			return err
		}
		vdirModified := info.ModTime().Truncate(time.Second)
		content, err := os.ReadFile(vdirFile)
		if err != nil {
			return err
		}

		if err = sync.UpdateResource(uid, string(content), vdirModified); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "Usage: decsync-vdir /path/to/decsync/contacts/uuid /path/to/vdir .vcf")
		os.Exit(1)
	}

	deviceName, err := os.Hostname()
	assert(err)
	if isUnsafeFilename(deviceName) {
		fmt.Fprintf(os.Stderr, "Warning: This system's hostname (%q) cannot "+
			"be used as a filename, read-only mode enabled.\n", deviceName)
		deviceName = ""
	}

	sync := DecSyncFolder{
		directory:  os.Args[1],
		deviceName: deviceName,
	}

	syncExists, err := sync.Exists()
	assert(err)
	if !syncExists {
		fmt.Fprintln(os.Stderr, "Error: The specified DecSync directory doesn't look valid!")

		// Try to print a more helpful error message
		possiblyRootDecsyncDir, err := isDir(sync.directory + "/contacts")
		assert(err)
		if !possiblyRootDecsyncDir {
			possiblyRootDecsyncDir, err = isDir(sync.directory + "/calendars")
			assert(err)
		}

		if possiblyRootDecsyncDir {
			fmt.Fprintf(os.Stderr, "Try using %[1]s/contacts/<UUID> or "+
				"%[1]s/calendars/<UUID> instead.\n", sync.directory)
			fmt.Fprintf(os.Stderr, "<UUID> can be found with "+
				"`ls %q/{contacts,calendars}`\n", sync.directory)
		} else {
			fmt.Fprintf(os.Stderr, "If know what you're doing, you can run "+
				"`mkdir %q` to ignore this error.\n", sync.directory+"/v2")
		}
		os.Exit(1)
	}

	// fmt.Println("Syncing...")
	err = SyncVdir(&sync, os.Args[2], os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
		os.Exit(1)
	}
	// fmt.Println("Synced!")
}
