// Code generated by go-bindata. DO NOT EDIT.
// sources:
// examples/arrays.cdc (879B)
// examples/arrays.cdc.abi.json (2.392kB)
// examples/car.cdc (733B)
// examples/car.cdc.abi.json (1.386kB)
// examples/dictionares.cdc (304B)
// examples/dictionares.cdc.abi.json (2.254kB)
// examples/events.cdc (483B)
// examples/events.cdc.abi.json (216B)
// examples/functions.cdc (409B)
// examples/functions.cdc.abi.json (1.232kB)
// examples/resources.cdc (492B)
// examples/resources.cdc.abi.json (1.416kB)

package abi

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes  []byte
	info   os.FileInfo
	digest [sha256.Size]byte
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _arraysCdc = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x94\x92\x3d\x6f\xdd\x20\x18\x85\x77\xff\x8a\x33\x62\xc5\x8a\xfc\xb1\xd9\x45\x51\x86\x0e\x99\x3a\x74\x44\x0c\x84\x0b\xbd\x48\x5c\x62\x61\x68\x95\x46\xf9\xef\x15\x18\xc7\xbe\xd5\x55\x3f\x16\x4b\xbc\x1c\x9f\xf7\x3c\x3e\x9e\xe3\x33\x74\x74\x10\xa7\x93\xf2\x44\x8c\x60\x4f\x2e\xf0\x7a\xc4\x93\x0b\x0f\x78\xab\x2a\x00\x46\x43\xdc\x5b\xe5\xbe\x85\x33\x28\x45\x8b\xb7\x34\x85\x57\x21\x7a\x07\x67\x6c\x3a\xbe\x67\xe9\x77\xe1\x61\x40\xd1\x6e\x87\x25\x5e\xb2\x57\x9e\xa5\xe1\x8f\xb3\xb1\x0a\x06\x9f\x76\xcf\xd5\x6e\x89\x17\xd0\xfc\xbc\x83\x60\x86\x4f\x79\x9a\xcc\x0c\xee\xba\x75\xc5\xbe\x75\x89\x97\xea\xbd\xaa\xaa\x2d\xff\x4f\x33\x7f\xd1\x43\x06\x78\x74\xaf\x5f\x83\x8f\x32\x4c\x03\x6f\xf0\x3c\x26\xa2\x69\x48\x4c\xec\x70\xd7\xf3\x69\xe0\x05\x10\x56\x05\xc8\xee\xea\xdd\x9e\x83\x82\x09\xd6\x26\x0f\xd6\x72\xbe\x0b\xfb\x9b\xc2\x2e\x0b\xbb\xa3\x70\xb8\x29\xec\xb3\xb0\xe7\xfc\xb0\xfb\x56\x36\x0a\x26\xbb\x06\xb2\x6f\x20\x87\x22\x2e\xf4\x32\xb1\x6f\xe8\x52\x58\xfb\x68\x2d\xd1\xd1\xc9\x60\x5e\xdc\x02\xbd\x8c\x60\x84\xd4\xe3\x87\xe5\x43\x9d\xf9\xf7\x33\x2f\x5f\xfd\xaa\xb0\x9c\xc5\xab\xf0\x9b\x92\x82\x95\xf5\x6b\x79\x24\xb5\xa7\x97\x52\x5f\x5d\x9c\x4a\xbc\x7b\x31\xcf\xca\x9d\x88\x5e\x98\xe1\xa4\xae\x3f\xee\x0c\x35\x6b\x8d\xe5\x57\xd9\x58\xbc\x0a\x47\x1a\xfd\xe2\x3f\x0b\x79\x26\xc2\x7b\xf1\x7a\x1d\xa4\x81\x1e\x41\xc8\x01\xea\x08\x58\x8f\x7f\xc4\xfb\x5f\xbe\xbc\xff\x2f\x88\x6b\x48\x66\xf8\x3f\x63\xfe\x0a\x00\x00\xff\xff\x2d\x70\xbe\xea\x6f\x03\x00\x00")

func arraysCdcBytes() ([]byte, error) {
	return bindataRead(
		_arraysCdc,
		"arrays.cdc",
	)
}

func arraysCdc() (*asset, error) {
	bytes, err := arraysCdcBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "arrays.cdc", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x4d, 0xa6, 0x65, 0x71, 0x99, 0x4a, 0xfb, 0xcc, 0x75, 0x1f, 0xdc, 0x65, 0x83, 0xd0, 0xa8, 0x2b, 0x5a, 0x60, 0xc8, 0x59, 0xab, 0xe4, 0xd1, 0x5f, 0xc8, 0xfd, 0x14, 0x41, 0x85, 0x24, 0x51, 0xf5}}
	return a, nil
}

var _arraysCdcAbiJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xd4\x54\x31\x6f\xb3\x30\x10\xdd\xf9\x15\xa7\x9b\x33\x7d\xd9\xb2\x65\xf8\x86\x4e\x1d\xda\xad\xca\x70\x01\x5b\x45\x22\x06\x19\x33\x90\x8a\xff\x5e\x19\x9a\x00\xf6\x11\x4c\x05\x6a\x3b\x44\x89\x9f\x2f\x77\xf7\xee\xbd\xf3\x47\x04\x80\x89\x90\xa9\x4a\x4d\x9a\xab\x12\x0f\x60\x21\x00\xa4\x24\x11\xfa\x7e\x04\x40\x59\xa9\xd8\xc6\x0c\x30\x00\x2c\x48\xd3\x45\x18\xa1\xed\x5f\xdf\xee\x38\x0c\x62\xda\x38\x45\x17\x81\x07\x40\xc2\xdd\xf8\xc2\xd4\x85\x18\xa5\xfc\xc2\x49\x6b\xaa\x99\x0b\x00\xcc\xa5\xcd\xf4\xa4\x0c\x3a\x77\x4d\x34\x75\xea\x7f\x9f\xfa\xfa\xa8\x85\xa9\xb4\x7a\xf5\x3b\xc0\xbc\xb0\x54\x29\xf3\x0a\xdd\x12\x75\xdf\x4d\x97\x0c\xaf\x69\xf1\x2c\xf7\xbf\x79\x5a\x47\x55\xbf\x18\x5d\xc5\xc6\xc9\xd8\x86\x94\xe9\xd5\x66\xdd\x87\x8f\x73\x37\xdf\xfb\x79\x55\xa5\x57\xe9\x7a\xa1\x09\xf8\xc6\xba\xa6\xb6\x51\xe0\xdf\x63\x2e\xce\x40\x99\x01\x34\x33\x46\x8d\x29\xcb\x8e\x99\xb5\xf5\xda\x56\x95\xa5\xab\x77\x46\x67\xd1\x2e\xd0\xad\x80\x17\xf1\x5d\x47\xf8\xf8\x14\x8d\x51\xc4\xa4\xd2\xe3\x0a\x83\xd5\xef\x35\x63\xa3\x1b\x06\xf5\x31\x17\xf9\x21\x83\x06\xf0\xe2\x7b\xe1\x9d\x24\x73\xfd\x9f\xe2\xf7\x0d\x9c\xd4\xb1\xda\xd2\x2a\x81\x12\x2f\x10\x2e\xe0\x3d\x94\xa1\x94\x1e\x1a\x79\x7a\x9a\x7c\xf9\xa5\x9c\x39\x03\x9f\x98\x07\x6b\x76\x97\x36\x18\xf2\x5f\xd8\x8e\xc8\x7e\x9a\xe8\x33\x00\x00\xff\xff\x5a\x5a\x6a\x40\x58\x09\x00\x00")

func arraysCdcAbiJsonBytes() ([]byte, error) {
	return bindataRead(
		_arraysCdcAbiJson,
		"arrays.cdc.abi.json",
	)
}

func arraysCdcAbiJson() (*asset, error) {
	bytes, err := arraysCdcAbiJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "arrays.cdc.abi.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x9b, 0x34, 0x4, 0x0, 0xe9, 0x7f, 0x20, 0xef, 0xa6, 0x74, 0x91, 0x10, 0xf8, 0x3a, 0x3d, 0x32, 0xf5, 0x2, 0xb4, 0x26, 0x97, 0x51, 0xbd, 0x7d, 0xaa, 0x6c, 0xc3, 0x18, 0x8e, 0x49, 0xd9, 0xda}}
	return a, nil
}

var _carCdc = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x84\x92\x31\x4f\xc3\x30\x10\x85\x77\xff\x8a\xa3\x53\x5b\x55\x84\xb6\x5b\x50\x85\x44\xa5\x4a\x0c\x4c\x8c\x55\x06\x93\x5c\x21\xaa\xed\x58\xe7\x4b\x01\xa1\xfe\x77\x74\x76\x1a\x5a\x08\x22\x83\x7d\xb9\x67\xe7\xbe\x3c\x3d\xdf\x3e\x83\x41\x86\xe0\x11\x2b\x58\xc1\xc8\xea\xf7\xda\xb6\x76\xa4\x94\x48\x81\xa9\x2d\x19\xd6\x9a\xe0\x53\x01\x00\x48\xf3\xa0\x09\x6c\x53\xa1\xc9\xe1\x89\xa9\x76\x2f\x97\x8a\xde\xe3\xa0\xc0\x54\xdb\x5e\x88\x4a\xed\x6a\x1e\xef\x5a\x63\x9c\xb6\xfd\x9d\x49\x37\x49\x9e\x80\x66\x77\x1d\x47\x09\xda\xe8\x47\x5f\xef\x71\xa0\x2d\x63\xbe\xdb\x47\xa5\xb2\x69\xac\xb2\x0c\x1e\x5b\xc3\xb5\x37\x08\x65\xe3\xd2\x9f\x35\x14\x40\x13\x82\x6b\x18\x42\xeb\x7d\x43\x8c\x15\x7c\x20\x5f\x9d\x11\x7a\x4d\xda\x86\x1c\xb6\x09\xf0\x76\x59\xfc\xc9\x98\x8e\x6e\x6f\x8a\x41\xd4\x4e\x9d\x17\x83\xc4\x9d\xba\x28\x4e\xe0\x3d\x40\x32\x3b\x4d\x9f\x25\x83\x4f\x2f\xd1\xd4\x7f\x8c\x8b\xfb\x20\x90\x6c\x83\x2c\xb2\x75\x18\xb2\x4e\x33\x75\xbc\x08\xc4\xc6\x20\xf2\x59\x24\x24\x42\xa5\x26\x31\x69\xad\xa9\x38\x63\x2f\x35\xcd\x73\x09\xd0\x4c\x0e\x2c\x62\x79\x17\xeb\x65\xaa\x7f\x61\xcb\x77\x60\x05\x5b\xb9\x79\xf2\xe2\xa8\x14\x1e\xd0\x31\x6c\xd0\x55\x48\xf7\x71\x1d\xbf\xbd\x22\x21\x78\xa3\xcb\x3e\x3d\x33\x28\x9b\xc0\x39\x3c\x38\x9e\xa8\xaf\x00\x00\x00\xff\xff\x97\xed\x9f\x35\xdd\x02\x00\x00")

func carCdcBytes() ([]byte, error) {
	return bindataRead(
		_carCdc,
		"car.cdc",
	)
}

func carCdc() (*asset, error) {
	bytes, err := carCdcBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "car.cdc", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x1a, 0x65, 0x83, 0x19, 0xa2, 0x5c, 0x45, 0xb7, 0x6e, 0xe7, 0x81, 0x1b, 0x2f, 0x4f, 0xb3, 0xee, 0x31, 0xcb, 0xa1, 0x71, 0x6b, 0x91, 0x9a, 0x68, 0xbf, 0xad, 0xfd, 0x26, 0x3, 0x6b, 0xb9, 0x91}}
	return a, nil
}

var _carCdcAbiJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xcc\x94\xc1\x4e\xc3\x30\x0c\x86\xef\x7d\x0a\xcb\xe7\x5d\x80\xdb\x8e\x20\x21\x71\xe6\x88\x38\x78\xad\x0b\x11\x69\x5a\xb9\xde\xd0\x40\x7d\x77\xd4\x8c\x0d\x27\x6b\x05\x63\x42\xe2\x32\x25\xff\x1f\xc7\x9f\xbd\xb8\xef\x05\x00\x56\x5c\xbb\xe0\xd4\xb5\xa1\xc7\x25\x8c\x12\x00\xde\x90\x1c\x36\x00\xd8\xab\xac\x4b\x35\x0a\x00\xd6\x8e\x7d\xd5\x27\x1a\x00\x36\x6d\xc5\x1e\x97\x80\xf7\x2a\x2e\x3c\xe1\x22\x31\xe9\x85\xe7\x3c\x15\xd7\x18\xef\x60\x0d\x5f\xa7\x30\x72\x92\x77\x6f\x2c\x63\xe2\x07\x13\x6f\xd7\x90\x20\xc5\xc8\x40\x4d\xcc\x5c\xaf\xbd\x8f\xeb\x45\x7e\x42\xb7\x1d\x4f\xe5\x8f\x0c\x66\xf7\x58\xe4\xab\x9d\xfb\xc9\x89\xb7\x9e\x59\x7f\xd7\xbb\x92\x24\xd7\x00\x90\x44\x68\x7b\x24\x03\x60\x5b\x4f\xa8\x36\x61\xfc\x17\x33\x7f\x98\x2d\x6c\xf8\xa3\x96\x97\x24\x17\xb3\xed\x3e\x13\x7f\xf1\x63\x84\xcb\x53\x10\xda\x6e\x1c\x07\xf2\x93\xee\x77\x88\x39\xe4\x19\xd0\x57\xff\x07\xfa\x94\x09\xe0\x50\xb1\x5c\xc7\x5f\x3b\x08\xbc\xe1\xa0\xc9\x1b\x4a\x5e\xff\xbe\xee\xce\x53\x99\xce\x27\x7a\x5a\xed\x3e\x2a\xaf\xcf\x2c\x99\x37\x37\xb7\xa6\xcd\x93\x69\xca\xb6\xd7\xe9\x9b\xee\x82\x9a\x6b\x0a\x5b\xea\xbe\xc4\xbe\x63\xae\x6c\x6d\x1b\x12\x47\x2b\x7f\x44\x32\x86\x0f\xc5\x50\x7c\x04\x00\x00\xff\xff\x01\x79\x63\xff\x6a\x05\x00\x00")

func carCdcAbiJsonBytes() ([]byte, error) {
	return bindataRead(
		_carCdcAbiJson,
		"car.cdc.abi.json",
	)
}

func carCdcAbiJson() (*asset, error) {
	bytes, err := carCdcAbiJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "car.cdc.abi.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x53, 0x8c, 0x65, 0x7c, 0xf0, 0xfd, 0xce, 0x82, 0xe3, 0x97, 0xe8, 0x10, 0x8e, 0xfa, 0x61, 0xc7, 0x9b, 0x95, 0x0, 0x9f, 0x37, 0xf8, 0x51, 0x4a, 0x77, 0x62, 0x8b, 0x46, 0x5f, 0x99, 0x93, 0x5f}}
	return a, nil
}

var _dictionaresCdc = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x6c\x8e\xb1\x8a\xc3\x30\x10\x44\x7b\x7d\xc5\x94\x16\xb8\xb8\x6b\x17\x0e\x73\x45\x0a\xd7\x2e\x8d\x0b\xd9\x91\x92\x80\x90\x8c\xb4\x2a\x82\xf1\xbf\x07\x4b\x21\x71\x88\xab\x61\x66\x77\xdf\xec\x9c\x46\x58\xcd\x18\xbd\xb7\x11\x7f\x58\x04\x00\xfc\x10\x8c\xb2\x51\xd7\xd9\xfd\x12\x38\x24\x2d\x56\x21\xb6\x75\x93\x1c\x8c\x0f\x27\x35\x5d\xab\x33\x61\xe9\x38\xdc\xdc\x85\x50\x74\xad\x61\x08\x55\x55\x5c\x5d\x44\xd2\xbf\xbb\x77\x1c\xd2\xc4\x8d\x94\x84\xfe\x6d\x87\x67\x65\xd0\x9c\x82\x43\x3f\xec\x6b\x38\x28\x17\x67\x1f\xf5\x51\x91\xfc\x8e\x3e\x59\xcb\xba\x67\x4d\xca\xda\x8c\x69\x1d\x6f\x0f\xb6\x8e\x25\xf5\xe5\xb0\x19\x64\xc6\xe5\xd1\x2b\x3b\xc2\x3d\x02\x00\x00\xff\xff\x51\xa4\x70\xea\x30\x01\x00\x00")

func dictionaresCdcBytes() ([]byte, error) {
	return bindataRead(
		_dictionaresCdc,
		"dictionares.cdc",
	)
}

func dictionaresCdc() (*asset, error) {
	bytes, err := dictionaresCdcBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dictionares.cdc", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0xca, 0x49, 0x68, 0xbb, 0xfc, 0x52, 0x65, 0x6a, 0x2, 0xd8, 0xe4, 0x78, 0x60, 0x37, 0x8d, 0x76, 0xd6, 0x5a, 0x53, 0x3a, 0xb7, 0x62, 0x50, 0xc6, 0x85, 0xdb, 0x2c, 0xf0, 0xed, 0x70, 0x86, 0xb3}}
	return a, nil
}

var _dictionaresCdcAbiJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xe4\x55\x41\x4f\xf3\x30\x0c\xbd\xf7\x57\x58\x3e\xef\x17\x7c\xb7\x0f\x89\x03\xe7\x71\x43\x1c\xbc\x2e\x85\x88\x2c\xa9\xbc\x74\x52\x85\xf2\xdf\x51\x0a\x8c\x26\x75\xba\x00\xe2\x80\x98\x34\x4d\xb5\xdd\xf8\xbd\x17\xfb\xed\xb9\x01\xc0\xbd\xea\xb4\xd5\x5e\x3b\x7b\xc4\x7f\x10\x43\x00\xb8\x73\xce\x7c\x3c\x02\xe0\x89\x58\xd3\xce\xa8\x59\x6c\x8a\xef\x75\x1b\x5f\x25\x1e\xb3\x0c\x00\x3e\xa9\x31\x9e\x81\x37\xd6\xe3\x26\x4d\x9d\xc8\x0c\x6a\x4a\x5e\x39\x67\xf0\x9c\x0c\xcd\xfc\x37\xbc\xbe\x85\x9d\xe3\x6b\x6a\x1f\xe7\x78\xba\xc1\x4e\x8d\x93\xae\xd8\x13\xd3\x41\x79\xc5\xf1\xe8\xbb\x59\xcb\x0c\x99\xa5\x43\x64\x82\xfb\x1c\x97\x1f\xfb\x9c\xe2\x25\x9a\x09\xd5\xad\x67\x6d\x1f\xb2\x53\x33\xc6\x6f\x35\x59\x49\x68\x4a\x4f\x61\x73\x99\x48\x57\x4b\x44\xd4\xed\x9c\x2d\xea\x77\xae\x28\x12\x84\x12\x31\x80\x7b\x41\x0e\x56\x7e\x60\x7b\x2b\xa3\x9c\x2a\x5c\x3f\x29\x6e\x22\xbd\xff\x76\xdc\x7a\x1e\x5a\xbf\x3c\x3c\xd4\xeb\xd8\x08\x80\xca\x40\x90\x98\x49\x98\x6a\xd7\x49\xba\x56\xa0\x95\xb1\xc8\x13\xef\x99\xec\xb1\x77\x47\xf5\x57\x67\xfe\x93\x77\x55\x63\x43\x22\xce\x55\x8c\x97\x6e\xa9\x25\x63\x7e\xc1\x05\x2d\xfd\x37\x65\x2e\xae\xdf\xaa\x51\xac\xf3\x4a\xaa\x62\x73\x31\x27\xb8\x02\x54\x39\x03\x94\x97\x33\x29\x11\x17\x35\xad\x98\x2d\x6d\xc9\xbc\xde\x3f\xb9\xcf\xac\xc7\xa5\xe8\x32\xf6\x73\xde\xf5\xdd\xbf\xe5\xc5\xac\x95\xf5\x2e\xeb\x5c\xa5\xef\x57\x34\xc8\xb6\xb1\x89\xdf\xd0\xbc\x04\x00\x00\xff\xff\xbe\x75\xe8\x85\xce\x08\x00\x00")

func dictionaresCdcAbiJsonBytes() ([]byte, error) {
	return bindataRead(
		_dictionaresCdcAbiJson,
		"dictionares.cdc.abi.json",
	)
}

func dictionaresCdcAbiJson() (*asset, error) {
	bytes, err := dictionaresCdcAbiJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dictionares.cdc.abi.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x45, 0x12, 0x3f, 0x2, 0x7c, 0xe1, 0xe7, 0xc2, 0xf0, 0xf6, 0xe2, 0xee, 0x77, 0x3f, 0x7d, 0x81, 0xbf, 0xf2, 0x16, 0x46, 0xb, 0x30, 0x22, 0x4e, 0x88, 0xf2, 0xf2, 0x32, 0x5e, 0xb1, 0xf3, 0x2c}}
	return a, nil
}

var _eventsCdc = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x64\x90\x3d\x6f\xf2\x40\x10\x84\xfb\xfb\x15\x53\x02\x42\xaf\xf5\x36\x29\x4e\x42\x89\x42\x1a\x2a\x0a\x48\x85\x10\x32\xbe\x35\x5e\xc5\xec\xa1\xbb\x75\xac\x08\xf1\xdf\x23\x9f\x6d\xf2\xe5\x72\x3c\xcf\x3c\xf6\x66\x33\x63\xb2\x0c\xdb\xf5\xcb\x1a\xcb\x26\x04\x12\xad\x3f\x40\xef\x24\x1a\x51\xe4\x22\x5e\x51\x78\xd1\x9c\x05\x81\xa2\x6f\x42\x41\x11\x79\x44\xc9\x54\xbb\x39\x8e\x8d\x42\x2b\x8e\xe0\x88\x23\xb1\x9c\xd0\xfa\xf0\x46\x0e\x5e\x8c\x89\x1a\x9a\x42\xb1\x21\x72\xb8\x1a\x00\xb8\x34\x47\xd4\xa4\x60\x67\xb1\x12\x35\x29\x64\x61\x9d\x0c\xc9\x74\x28\x76\x4f\xa4\xba\xfc\xc7\x0e\x0b\xb0\x4b\xe1\xcd\xdc\x8c\x31\xe3\x67\x60\xeb\xcf\xb9\xfa\x5f\xcb\x91\xc8\x45\x8b\x5d\x27\xdd\x7f\xdb\xff\x91\xff\xb1\xa4\xb7\x58\xf4\xf4\x97\x2b\xdd\x01\xcb\xca\x5f\x2e\xe4\x26\x9a\x7c\x76\xf0\xce\xfb\xf2\xa1\xa6\x52\xef\xbb\x23\xb2\xad\x82\x6f\x27\x6d\x45\x81\x30\x62\x4f\x23\x57\xf9\xf6\x50\xe6\x01\x8e\xa3\xe6\x52\x90\xc5\xeb\x4a\xf4\xff\xc3\x9d\x7e\xf6\xcd\xa9\xd2\xc1\x47\xd1\xe2\xba\xd1\xc0\x72\xb2\xd8\xf5\x1b\x8f\xfb\xdb\xd4\xcc\xb2\xb1\xbf\xf1\x6d\xfa\x3f\x8b\xbe\x37\x87\xf2\xb9\xe3\xba\x83\x9a\xcf\x00\x00\x00\xff\xff\xd5\x08\x4c\x74\xe3\x01\x00\x00")

func eventsCdcBytes() ([]byte, error) {
	return bindataRead(
		_eventsCdc,
		"events.cdc",
	)
}

func eventsCdc() (*asset, error) {
	bytes, err := eventsCdcBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "events.cdc", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0xe4, 0x85, 0xb9, 0x1c, 0x7e, 0xc1, 0xcf, 0x1e, 0x35, 0x56, 0x33, 0xdc, 0xfa, 0xfb, 0xfd, 0x9a, 0xac, 0x7a, 0x84, 0x80, 0x79, 0x87, 0x41, 0x31, 0xb1, 0xa9, 0xc6, 0x8c, 0x57, 0xa8, 0x79, 0xf0}}
	return a, nil
}

var _eventsCdcAbiJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xaa\xe6\x52\x50\x50\x4a\x49\x4d\xcb\xcc\xcb\x2c\xc9\xcc\xcf\x2b\x56\xb2\x52\x00\x09\x29\x28\x28\x05\xe7\x97\xc3\x39\x0a\x0a\x4a\xa9\x65\xa9\x79\x25\x4a\x56\x0a\xd1\x50\x01\x05\xb8\x14\x58\x3a\x2f\x31\x37\x55\xc9\x4a\x41\xa9\x38\x35\x35\x45\x49\x07\x59\xa6\xa4\xb2\x00\x2c\x13\x5c\x52\x94\x99\x97\xae\x04\x97\xaa\xd5\xc1\x6f\x52\x49\x66\x6e\x6a\x31\x76\xa3\x3c\xf3\x4a\x90\xcc\x81\xb2\x62\xb9\x60\xbc\x5a\xae\x5a\x2e\x40\x00\x00\x00\xff\xff\xec\xdd\xac\x8f\xd8\x00\x00\x00")

func eventsCdcAbiJsonBytes() ([]byte, error) {
	return bindataRead(
		_eventsCdcAbiJson,
		"events.cdc.abi.json",
	)
}

func eventsCdcAbiJson() (*asset, error) {
	bytes, err := eventsCdcAbiJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "events.cdc.abi.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x39, 0xe9, 0xc5, 0xc8, 0x6e, 0x92, 0x72, 0x67, 0x6f, 0xa9, 0x36, 0xf2, 0x45, 0x11, 0xe2, 0xf1, 0xa2, 0x32, 0x60, 0x42, 0x49, 0x5, 0xfc, 0x53, 0xad, 0x33, 0x2d, 0x74, 0xe4, 0x17, 0x88, 0x19}}
	return a, nil
}

var _functionsCdc = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x64\x8f\x31\x4f\x03\x31\x0c\x85\xf7\xfb\x15\x6f\x74\x50\x25\xf6\xa2\x8a\xb9\x1b\x13\x7b\xee\x62\xa3\x48\xe0\x80\xeb\xa0\x93\xd0\xfd\x77\x94\xe3\x7a\x4a\x69\x06\x27\x7e\x71\xbe\xf7\xf2\x59\x47\x48\x55\x5c\xbe\xcc\x69\xc6\x7c\xc4\x59\x3d\xac\xf5\x67\x00\x00\x63\xaf\xa6\x98\x1f\xe6\x61\x19\x86\xeb\x78\xca\xdf\x39\xb1\xbd\x58\x49\x75\x62\xa3\xd6\x5f\x8a\x21\x5d\xdf\x13\xad\x7b\x2b\xb8\x01\x49\x55\x8a\xf6\x56\x3f\x58\x7d\xb7\x3b\xab\x6f\x53\xbd\xe5\x63\x7a\x5a\xb5\xe5\xc6\x99\xa7\x62\xd1\x8b\x91\x54\x9d\x3c\x17\x85\x34\xbb\x70\x7c\x2d\x39\x85\x03\x46\x96\x62\xdc\x49\xcf\x07\x44\x71\xb6\x5e\x0a\x5d\x73\x97\x0f\x14\xba\x34\x59\xf0\xce\x8e\x11\xa7\x0d\xdd\xdd\xb5\x35\x52\xd8\xfb\x65\x3f\x49\xa7\x6e\x84\x88\xd3\x5f\x90\x7f\x80\x78\x07\x68\x1f\xfe\x0d\x00\x00\xff\xff\x73\x4e\xca\x61\x99\x01\x00\x00")

func functionsCdcBytes() ([]byte, error) {
	return bindataRead(
		_functionsCdc,
		"functions.cdc",
	)
}

func functionsCdc() (*asset, error) {
	bytes, err := functionsCdcBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "functions.cdc", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x35, 0x7, 0xdc, 0xa3, 0x25, 0xd5, 0x27, 0xcf, 0x2d, 0x30, 0xc3, 0x50, 0x31, 0xe5, 0x8f, 0xf3, 0x35, 0x43, 0x83, 0x4a, 0x7a, 0xef, 0x42, 0x24, 0x6b, 0xb9, 0x88, 0xb2, 0xaa, 0x14, 0x1c, 0x71}}
	return a, nil
}

var _functionsCdcAbiJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xbc\x52\x41\x4e\xc4\x30\x0c\xbc\xf7\x15\x96\xcf\xfb\x82\xfd\x01\x37\x0e\xdc\x10\x87\x6c\xe3\x48\x91\xba\x49\x71\x5d\x04\x5a\xe5\xef\x28\xad\x14\x92\x92\x14\x10\x85\x43\xa5\xda\x33\xce\x8c\x47\xbe\x75\x00\xa8\xc9\x58\x67\xc5\x7a\x37\xe1\x19\x62\x0b\x00\xa7\x67\x96\x54\x01\xa0\x99\x5d\x1f\x29\x59\x0f\x00\x47\xc5\xea\x4a\x42\x1c\x27\x1f\x53\x1f\x32\xce\xc2\x73\xea\x4a\x78\x06\x7c\xc5\x53\x09\x0c\xea\x42\x43\x15\x91\xb7\x71\x19\xb9\x73\x82\x19\x12\xd2\xff\xd3\xc7\x00\x32\xc9\xcc\xee\xe1\xf3\xc8\x4a\x0f\x2b\x15\xb5\x7d\xb1\x9a\xf8\x9e\xbd\x9e\x7b\xe2\xe3\xf7\xd3\xcd\xfd\xa2\xf4\xe4\xf9\xb8\x2d\x73\x07\x75\xf7\xfb\x1b\x2c\xe8\x46\xb6\x90\xdb\x0f\xb6\x74\x19\xea\x71\x53\xef\x59\x89\xff\x83\xa0\x4d\x33\xe8\xf4\x7e\x3d\xe9\xdb\x36\x82\xdc\x4f\x28\xc0\xbc\x0a\xa7\xaf\x3d\x5d\xc8\x78\xa6\xef\xea\xfa\x31\xaa\xaa\xa1\x82\xed\xba\x2a\x7d\xfd\xdc\xa5\x32\x42\xad\x33\xfc\x1f\x93\xbf\xb8\xed\xe6\xc5\x75\xf1\x0b\xdd\x7b\x00\x00\x00\xff\xff\x43\xef\xaf\x0b\xd0\x04\x00\x00")

func functionsCdcAbiJsonBytes() ([]byte, error) {
	return bindataRead(
		_functionsCdcAbiJson,
		"functions.cdc.abi.json",
	)
}

func functionsCdcAbiJson() (*asset, error) {
	bytes, err := functionsCdcAbiJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "functions.cdc.abi.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x9, 0x2f, 0x7c, 0x7b, 0xa0, 0xc4, 0x65, 0xf3, 0xe0, 0x8a, 0x7f, 0x8, 0xa2, 0x2d, 0x98, 0x59, 0xfe, 0xb, 0xb6, 0x44, 0xf2, 0xe8, 0x54, 0xf4, 0x91, 0x38, 0x97, 0xef, 0x46, 0x4f, 0x61, 0xe9}}
	return a, nil
}

var _resourcesCdc = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x74\x8f\x31\x6b\xc3\x30\x14\x84\x77\xfd\x8a\x1b\x5d\x70\x3b\x17\x53\xd1\xd2\x4e\x9d\x32\x65\x0a\x1e\x2c\x45\x76\x0c\x46\x0a\x4f\xd2\x10\x82\xff\x7b\xb0\x24\x1b\xcb\x4e\xb4\x08\xbe\xf7\xee\xdd\xdd\xd5\x0b\x58\x47\x5e\x3a\xfc\x99\xc1\x78\xc2\x9d\x01\xc0\xc4\x07\xe5\x40\x15\x8e\xff\xda\x7d\x66\xb0\x7b\x06\xc5\x0c\x03\xed\x75\xef\x8a\x59\x5c\x2e\x8a\x72\x59\x7b\x4b\x46\xd3\xb3\x6a\x68\x3f\x08\x1c\x94\xa3\x0e\x1c\x5d\x8e\x04\x38\x44\x40\x23\x1b\x19\x9b\xcc\x49\x59\xe3\x49\x2a\xfc\x36\xba\xd1\xcd\xa6\x80\x0c\xad\xaa\xd4\x6e\x15\x2e\x1f\xec\xe2\xc4\x31\x78\x3a\xf0\xca\xd2\x6b\x79\x39\xb4\xd1\xd9\x6e\xac\x45\xa4\x15\x7e\x4e\x71\xe1\xbb\x5e\xf9\xef\xa6\xf5\x2e\x43\x5a\xc1\xd7\xfb\x7c\x2b\xc5\x08\xdf\x59\x59\x47\xe6\x56\xac\x65\x89\x65\xf2\x25\xfa\x23\x00\x00\xff\xff\x2c\x96\xc5\xf3\xec\x01\x00\x00")

func resourcesCdcBytes() ([]byte, error) {
	return bindataRead(
		_resourcesCdc,
		"resources.cdc",
	)
}

func resourcesCdc() (*asset, error) {
	bytes, err := resourcesCdcBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "resources.cdc", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0xfc, 0xbc, 0xa8, 0xf8, 0x1a, 0x83, 0x8c, 0x44, 0xe0, 0x3f, 0xd2, 0xa7, 0xce, 0x4c, 0x49, 0x19, 0xe8, 0xdd, 0x1b, 0x73, 0xc1, 0x2f, 0xe8, 0x9a, 0xda, 0x2b, 0xea, 0x33, 0x2b, 0xb5, 0x11, 0xd9}}
	return a, nil
}

var _resourcesCdcAbiJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xb4\x93\xb1\x4e\xc4\x30\x0c\x86\xf7\x3c\x85\xe5\x99\x07\x40\x8c\x30\x31\x31\x31\x21\x06\xb7\x97\x1e\x91\x4a\x72\x72\xd2\xe1\x40\x7d\x77\x94\x5e\xdb\x4b\xd3\xe4\x68\x10\x1d\x4e\x6a\x7e\xc7\xf6\x9f\xcf\xbe\x6f\x01\x80\x07\xd9\x28\xad\x9c\x32\xda\xe2\x03\x78\x09\x00\x9f\x4c\x6b\x3a\x9e\xcf\x00\x68\x1d\x77\xb5\x0b\x14\x00\x6c\x94\x6c\x0f\x76\xa1\x01\xa0\x4f\xc3\xd7\x67\xed\xee\xf1\x2e\xd4\x8f\x19\xbd\xba\xea\xb3\xdc\x5f\x6f\xe0\xe0\x8e\x5a\xf5\x25\xd9\xf7\x7a\x0b\x72\xc3\x6f\x58\xb8\x18\x32\x35\x7d\x4a\x5f\x9c\x17\x0d\x87\x90\x3b\x9f\x64\xa2\x6f\xd4\xfb\x66\xd5\xe3\x2e\x55\xab\xb2\xaa\xc1\xe9\x5d\xc4\x5f\x97\xe8\xd8\x19\x1f\x49\x93\xa6\x70\xa6\x2c\xad\xe9\xb8\x96\x5b\xa6\x5a\xc7\x1b\x31\xea\xf3\x5e\x4c\x3b\x23\x52\xee\xfe\x77\x9e\xa3\x97\x1c\xa8\x38\xef\x17\x97\x31\xc7\x42\xaa\x9d\xae\x3f\x5e\x9a\x0b\x5c\xfb\x57\xba\xd5\x2a\x7d\x0c\x10\x33\x9d\x13\x6f\x42\xd3\xa4\x5f\x6a\x4e\xfe\xaf\x4c\x6d\x32\xba\x74\x35\x6d\xc4\xea\x5a\xbf\x99\xce\x5e\x13\x9e\x78\x14\x8c\x38\x47\x0a\x6e\xd0\x82\xad\x44\xd6\x4c\x4a\x28\x65\x77\x48\xf8\x5f\x2f\x7e\x02\x00\x00\xff\xff\x87\x20\x62\xe9\x88\x05\x00\x00")

func resourcesCdcAbiJsonBytes() ([]byte, error) {
	return bindataRead(
		_resourcesCdcAbiJson,
		"resources.cdc.abi.json",
	)
}

func resourcesCdcAbiJson() (*asset, error) {
	bytes, err := resourcesCdcAbiJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "resources.cdc.abi.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x9a, 0x4, 0xd0, 0x4b, 0xd, 0xa2, 0xf9, 0x41, 0x82, 0xa1, 0x4a, 0xd, 0xf7, 0xe7, 0xc7, 0xf2, 0xac, 0x56, 0x89, 0xa, 0xf8, 0x10, 0x77, 0x87, 0xff, 0xb2, 0xa9, 0x6a, 0x5, 0xd2, 0x57, 0x85}}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// AssetString returns the asset contents as a string (instead of a []byte).
func AssetString(name string) (string, error) {
	data, err := Asset(name)
	return string(data), err
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// MustAssetString is like AssetString but panics when Asset would return an
// error. It simplifies safe initialization of global variables.
func MustAssetString(name string) string {
	return string(MustAsset(name))
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetDigest returns the digest of the file with the given name. It returns an
// error if the asset could not be found or the digest could not be loaded.
func AssetDigest(name string) ([sha256.Size]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("AssetDigest %s can't read by error: %v", name, err)
		}
		return a.digest, nil
	}
	return [sha256.Size]byte{}, fmt.Errorf("AssetDigest %s not found", name)
}

// Digests returns a map of all known files and their checksums.
func Digests() (map[string][sha256.Size]byte, error) {
	mp := make(map[string][sha256.Size]byte, len(_bindata))
	for name := range _bindata {
		a, err := _bindata[name]()
		if err != nil {
			return nil, err
		}
		mp[name] = a.digest
	}
	return mp, nil
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"arrays.cdc": arraysCdc,

	"arrays.cdc.abi.json": arraysCdcAbiJson,

	"car.cdc": carCdc,

	"car.cdc.abi.json": carCdcAbiJson,

	"dictionares.cdc": dictionaresCdc,

	"dictionares.cdc.abi.json": dictionaresCdcAbiJson,

	"events.cdc": eventsCdc,

	"events.cdc.abi.json": eventsCdcAbiJson,

	"functions.cdc": functionsCdc,

	"functions.cdc.abi.json": functionsCdcAbiJson,

	"resources.cdc": resourcesCdc,

	"resources.cdc.abi.json": resourcesCdcAbiJson,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"},
// AssetDir("data/img") would return []string{"a.png", "b.png"},
// AssetDir("foo.txt") and AssetDir("notexist") would return an error, and
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		canonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(canonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"arrays.cdc":               &bintree{arraysCdc, map[string]*bintree{}},
	"arrays.cdc.abi.json":      &bintree{arraysCdcAbiJson, map[string]*bintree{}},
	"car.cdc":                  &bintree{carCdc, map[string]*bintree{}},
	"car.cdc.abi.json":         &bintree{carCdcAbiJson, map[string]*bintree{}},
	"dictionares.cdc":          &bintree{dictionaresCdc, map[string]*bintree{}},
	"dictionares.cdc.abi.json": &bintree{dictionaresCdcAbiJson, map[string]*bintree{}},
	"events.cdc":               &bintree{eventsCdc, map[string]*bintree{}},
	"events.cdc.abi.json":      &bintree{eventsCdcAbiJson, map[string]*bintree{}},
	"functions.cdc":            &bintree{functionsCdc, map[string]*bintree{}},
	"functions.cdc.abi.json":   &bintree{functionsCdcAbiJson, map[string]*bintree{}},
	"resources.cdc":            &bintree{resourcesCdc, map[string]*bintree{}},
	"resources.cdc.abi.json":   &bintree{resourcesCdcAbiJson, map[string]*bintree{}},
}}

// RestoreAsset restores an asset under the given directory.
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	return os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
}

// RestoreAssets restores an asset under the given directory recursively.
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(canonicalName, "/")...)...)
}
